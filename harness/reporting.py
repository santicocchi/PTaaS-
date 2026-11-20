"""Informe del engagement (change 007): determinista, desde la bitácora, versionado y redactado.

    python -m harness.reporting reproduce --engagement <id> --report report-v<N> \\
        [--state-dir state] [--audit-dir audit]

`generate_report()` arma el informe por reglas, sin LLM (D1):
- el estado de validación de cada hallazgo sale SOLO de la bitácora (D6);
- CWE, vector CVSS v4.0 y remediación salen de la tabla curada (D3); si falta algo no se
  escribe ningún archivo y queda un `report.generation_failed` por hallazgo y campo;
- todo texto que viene de una herramienta pasa por `redact()` y el resultado final por
  `scan()` (D13);
- cada versión es inmutable (`open("xb")`) y reproducible: es una función pura de la bitácora
  hasta `audit_seq`, del snapshot sellado `inputs-v<N>.json` y de los archivos de evidencia
  (D2, D9). `reproduce` la vuelve a construir y compara byte a byte.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harness.analysis import FindingStore
from harness.approvals import ApprovalStore
from harness.assets import AssetGraph
from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import (
    REPORT_FAILED_ACTION,
    REPORT_GENERATED_ACTION,
    AuditSink,
    Entry,
    Result,
)
from harness.correlate import host_of
from harness.cvss4 import InvalidVector, parse_vector
from harness.engagement import Engagement, State
from harness.evidence import verify_evidence
from harness.poc.catalog import catalog_version as poc_catalog_version
from harness.redaction import SensitiveData, redact
from harness.report_catalog import ROOT, ReportCatalog, first_sentence, has_jargon
from harness.roe import RoE
from harness.schemas import CandidateFinding, PrioritizedVuln

GENERATOR_VERSION = "007.1"
AGENT = "report-builder"
CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,4}\Z")
REPORT_ID_RE = re.compile(r"^report-v([1-9][0-9]{0,5})\Z")
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
_FP_RE = re.compile(r"FP-[0-9]+")
POLICY = ROOT / "harness" / "policy.yaml"
PROFILES = ROOT / "harness" / "profiles.yaml"
FEEDS_MANIFEST = ROOT / "data" / "feeds" / "manifest.json"
CAPABILITY = "poc_catalog.run_parametrized"

FIELD_REASONS = {"cwe": "missing_cwe", "cvss_v4_vector": "invalid_cvss_vector",
                 "remediation": "missing_remediation"}
CLOSE_TEXT = {"no_catalog_entry": "sin verificación en el catálogo",
              "reviewer_rejected": "validación rechazada por el Reviewer",
              "reviewer_timeout": "no validado por falta de revisión",
              "request_budget_exhausted": "presupuesto de validación agotado"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "None")
SECTIONS = (
    ("1", "executive_summary", "Resumen ejecutivo"),
    ("2", "introduction", "Informe técnico — Introducción"),
    ("3", "information_gathering", "Recolección de información"),
    ("4", "vulnerability_assessment", "Evaluación de vulnerabilidades"),
    ("5", "sandbox_confirmation", "Confirmación en sandbox"),
    ("6", "post_exploitation", "Post-explotación"),
    ("7", "risk_exposure", "Riesgo y exposición"),
    ("8", "conclusion", "Conclusión"),
    ("A", "annex_audit", "Anexo A: bitácora"),
    ("B", "annex_evidence", "Anexo B: evidencias"),
    ("C", "annex_discarded", "Anexo C: descartados"),
    ("D", "annex_disclosure", "Anexo D: divulgación"),
    ("E", "annex_reproducibility", "Anexo E: reproducibilidad"),
)
METHODOLOGY = ["PTES", "NIST SP 800-115", "OWASP WSTG", "CVSS v4.0", "EPSS", "CWE"]
DIFF_FIELDS = ("title", "severity", "cvss_v4_vector", "remediation", "business_impact",
               "technical_description", "references", "validation", "epss")


# ---- errores --------------------------------------------------------------------------------

class DeliveryNotApproved(Exception):
    """La entrega no tiene una aprobación vigente del Reviewer (gate de entrega, D14)."""


def deliver(report: dict[str, Any], reviewer_approved: bool) -> dict[str, Any]:
    """Entrega anterior al 007, que todavía nadie llama. La reemplaza el gate de D14 (segundo
    PR del change): ahí la aprobación sale de la bitácora y no de un booleano del llamador."""
    if not reviewer_approved:
        raise DeliveryNotApproved("la entrega requiere aprobación del Reviewer")
    return {**report, "delivered": True}


class ReportError(Exception):
    """El informe no se generó. `reason` es uno de REPORT_FAILURE_REASONS."""

    def __init__(self, reason: str, detail: str, subject: str | None = None) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail, self.subject = reason, detail, subject


class MissingField(ReportError):
    """Faltan campos obligatorios. `missing` lista (finding_id, campo) de TODOS los hallazgos."""

    def __init__(self, missing: list[tuple[str, str]]) -> None:
        self.missing = missing
        detail = "; ".join(f"{fid}: falta {name}" for fid, name in missing)
        super().__init__("missing_field", detail)


class PreviousReportError(ValueError):
    """Un informe anterior (`--previous`) que no se puede usar."""


# ---- huella e informes anteriores ----------------------------------------------------------

def fingerprint(asset_id: str, key: str) -> str:
    """Huella `fp1-<32 hex>` (D10): solo activo y clave, sin engagement ni fechas."""
    raw = json.dumps({"v": 1, "asset": asset_id, "key": key}, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=False)
    return "fp1-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _generated_refs(entries: Iterable[Entry]) -> dict[str, str]:
    """report_id → referencia del `report.generated` (el último, si hubiera dos)."""
    return {str(e["subject"]): str(e["evidence"]) for e in entries
            if e["phase"] == "control" and e["action"] == REPORT_GENERATED_ACTION
            and e["result"] == Result.OK.value and e.get("subject") and e.get("evidence")}


@dataclass(frozen=True)
class PreviousReport:
    engagement: str
    report_id: str
    sha256: str
    fingerprints: tuple[str, ...]


def load_previous(engagement_id: str, report_id: str, state_dir: Path | str,
                  audit_dir: Path | str) -> PreviousReport:
    """Un informe entregado de otro engagement, solo si su bitácora lo respalda (D10)."""
    if not _ENGAGEMENT_RE.match(engagement_id) or not REPORT_ID_RE.match(report_id):
        raise PreviousReportError("engagement o informe inválido")
    audit_path = Path(audit_dir) / f"{engagement_id}.sqlite3"
    if not audit_path.is_file() or verify_file(audit_path) is not None:
        raise PreviousReportError(f"{engagement_id}: bitácora ausente o rota")
    log = SqliteAuditLog.open(engagement_id, audit_dir)
    try:
        entries = log.entries
    finally:
        log.close()
    ref = _generated_refs(entries).get(report_id)
    delivered = any(e["action"] == "report.delivered" and e["result"] == Result.OK.value
                    and e.get("subject") == report_id for e in entries)
    if ref is None or not delivered:
        raise PreviousReportError(f"{engagement_id}/{report_id}: no figura entregado")
    if not verify_evidence(state_dir, ref):
        raise PreviousReportError(f"{engagement_id}/{report_id}: el archivo no coincide")
    rel = ref.split("#sha256=", 1)[0]
    doc = json.loads((Path(state_dir) / rel).read_bytes())
    fps = tuple(sorted(f["fingerprint"] for f in doc["findings"]))
    return PreviousReport(engagement_id, report_id, ref.split("#sha256=", 1)[1], fps)


# ---- estado de validación desde la bitácora (D6) -------------------------------------------

def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def validation_of(fids: set[str], entries: list[Entry],
                  state_dir: Path) -> dict[str, Any]:
    """Estado de validación de un hallazgo (o de varios con la misma huella)."""
    mine = [e for e in entries if e.get("subject") in fids]
    attempts: list[dict[str, Any]] = []
    positive = False
    for e in mine:
        if e["action"] != "validation.attempt" or e["phase"] != "control":
            continue
        ref = e.get("evidence")
        doc: dict[str, Any] = {}
        if ref:
            if not verify_evidence(state_dir, ref):
                raise ReportError("evidence_mismatch", f"la evidencia {ref} no verifica",
                                  str(e["subject"]))
            doc = json.loads((state_dir / ref.split("#sha256=", 1)[0]).read_bytes())
        ok = e["result"] == Result.OK.value
        is_positive = ok and doc.get("result") == "validated" and doc.get("truncated") is False
        positive = positive or is_positive
        attempts.append({"finding_id": e["subject"], "seq": entries.index(e) + 1,
                         "at": _ts(e["ts"]), "outcome": e["result"],
                         "result": doc.get("result"), "poc_id": doc.get("poc_id"),
                         "catalog_version": doc.get("catalog_version"),
                         "truncated": doc.get("truncated"), "evidence": ref})
    if positive:
        return {"status": "validated", "reason": None, "text": "Validado en sandbox",
                "attempts": attempts}
    closed = [e for e in mine if e["action"] == "validation.closed"]
    blocked = [e for e in mine if e["action"] == CAPABILITY
               and e["result"] == Result.BLOCKED.value]
    pending = [e for e in mine if e["action"] == CAPABILITY
               and e["result"] == Result.PENDING_HITL.value]
    if closed:
        reason = str(closed[-1].get("reason"))
        text = CLOSE_TEXT.get(reason, reason)
    elif blocked:
        reason, text = "blocked", "bloqueado por alcance"
    elif any(a["outcome"] == Result.OK.value for a in attempts):
        reason, text = "negative", "verificación negativa"
    elif attempts:
        reason, text = "sandbox_error", "error del sandbox"
    elif pending:
        reason, text = "pending_review", "pendiente de revisión"
    else:
        reason, text = "not_attempted", "no se intentó validar"
    return {"status": "not_validated", "reason": reason, "text": text, "attempts": attempts}


# ---- armado (función pura de las entradas) -------------------------------------------------

def _in_lab(host: str, lab: dict[str, list[str]]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        h = host.lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in lab["domains"])
    return any(ip in ipaddress.ip_network(c) for c in lab["cidrs"])


def _fmt_score(score: float) -> str:
    return f"{score:.1f}"


def _epss(c: dict[str, Any], epss_date: str | None) -> dict[str, Any]:
    if c.get("epss") is None:
        return {"value": None, "text": "sin dato"}
    value = f"{float(c['epss']):.3f}"
    if c.get("feed_stale"):
        return {"value": value, "text": f"{value} (dato desactualizado)", "date": epss_date}
    return {"value": value, "text": f"{value} (snapshot del {epss_date})", "date": epss_date}


@dataclass
class _Group:
    fingerprint: str
    candidates: list[dict[str, Any]] = field(default_factory=list)
    vulns: list[dict[str, Any]] = field(default_factory=list)


def _groups(inputs: dict[str, Any]) -> list[_Group]:
    cands = {c["id"]: c for c in inputs["candidates"]}
    groups: dict[str, _Group] = {}
    for v in inputs["vulns"]:
        c = cands.get(v["finding_id"])
        if c is None:
            continue
        fp = fingerprint(c["asset_id"], c.get("cve") or c["cwe"])
        g = groups.setdefault(fp, _Group(fp))
        g.candidates.append(c)
        g.vulns.append(v)
    return list(groups.values())


def build(inputs: dict[str, Any], entries: list[Entry], state_dir: Path,
          previous_version: dict[str, Any] | None = None) -> tuple[dict[str, Any], str]:
    """Informe (JSON canónico como dict) y su markdown. Lanza ReportError."""
    seq = int(inputs["audit_seq"])
    if seq < 1 or seq > len(entries):
        raise ValueError("audit_seq fuera de la bitácora")
    entries = entries[:seq]
    as_of = _ts(entries[-1]["ts"])
    catalog = ReportCatalog.from_entries(inputs["catalog"]["entries"],
                                         inputs["catalog"]["sha256"])
    lab = inputs["lab"]
    epss_date = inputs["feeds"].get("epss_date")
    assets = {a["host"]: a for a in inputs["assets"]}

    findings: list[dict[str, Any]] = []
    discarded: list[dict[str, Any]] = []
    missing: list[tuple[str, str]] = []
    for g in sorted(_groups(inputs), key=lambda g: g.fingerprint):
        statuses = {v["status"] for v in g.vulns}
        fids = sorted(v["finding_id"] for v in g.vulns)
        main = min(g.candidates, key=lambda c: c["id"])
        if statuses == {"discarded"}:
            discarded.append({"fingerprint": g.fingerprint, "finding_ids": fids,
                              "host": main["host"], "key": main.get("cve") or main["cwe"],
                              "false_positive_ids": sorted({i for v in g.vulns for i in
                                                            _FP_RE.findall(v["rationale"])})})
            continue
        for c in g.candidates:
            if not _in_lab(c["host"], lab):
                raise ReportError("not_lab_target", f"{c['host']} no es del laboratorio", c["id"])
        cwe = main["cwe"]
        entry, problems = catalog.lookup(main.get("cve"), cwe)
        fid = fids[0]
        if not CWE_RE.match(cwe):
            missing.append((fid, "cwe"))
        if entry is None:
            missing += [(fid, p) for p in problems if p not in ("cvss_v4_vector", "remediation")]
            missing += [(fid, "cvss_v4_vector"), (fid, "remediation")]
            continue
        try:
            vector = parse_vector(entry.cvss_v4_vector)
        except InvalidVector:
            missing.append((fid, "cvss_v4_vector"))
            vector = None
        if not entry.remediation.strip():
            missing.append((fid, "remediation"))
        if vector is None or not CWE_RE.match(cwe) or not entry.remediation.strip():
            continue
        validation = validation_of(set(fids), entries, state_dir)
        score = vector.score
        feed_score = next((c.get("cvss_score") for c in g.candidates
                           if c.get("cvss_version") == "4.0" and c.get("cvss_score") is not None),
                          None)
        priorities = [v["priority"] for v in g.vulns if v.get("priority") is not None]
        analysis = ("confirmed" if "confirmed" in statuses else "inconclusive")
        obs = sorted(
            ({"tool": o["tool"], "check": redact(str(o["check_id"])), "url": redact(o["url"]),
              "risk": o["risk"], "confidence": o["confidence"],
              "evidence": redact(str(o["evidence"]))[:200]}
             for o in inputs["observations"]
             if o["host"] in {c["host"] for c in g.candidates} and o["cwe"] == cwe),
            key=lambda o: (o["tool"], o["check"], o["url"]))
        host = main["host"]
        evidence = sorted({a["evidence"] for a in validation["attempts"] if a["evidence"]})
        high = vector.severity in ("High", "Critical")
        findings.append({
            "fingerprint": g.fingerprint, "finding_ids": fids, "host": host,
            "asset_id": main["asset_id"], "cve": main.get("cve"), "cwe": cwe,
            "title": entry.title, "technical_description": entry.technical_description,
            "business_impact": entry.business_impact, "remediation": entry.remediation,
            "references": [cwe, *entry.references], "catalog_entry": entry.key,
            "cvss_v4_vector": vector.text, "cvss_v4_score": _fmt_score(score),
            "severity": vector.severity,
            "feed_cvss": None if main.get("cvss_score") is None else {
                "score": _fmt_score(float(main["cvss_score"])),
                "version": main.get("cvss_version"),
                "differs": feed_score is not None and _fmt_score(float(feed_score))
                != _fmt_score(score)},
            "epss": _epss(main, epss_date),
            "priority": None if not priorities else f"{max(priorities):.2f}",
            "analysis_status": analysis,
            "analysis_text": ("confirmado por análisis" if analysis == "confirmed"
                              else "inconcluso en el análisis"),
            "validation": {k: validation[k] for k in ("status", "reason", "text")},
            "attempts": validation["attempts"],
            "manual_check": validation["status"] != "validated" and high,
            "observations": obs, "evidence": evidence,
            "technologies": list(assets.get(host, {}).get("technologies", [])),
            "recurrence": None,
        })
    if missing:
        raise MissingField(sorted(set(missing), key=missing.index))

    findings.sort(key=lambda f: (f["priority"] is None, -float(f["priority"] or 0),
                                 f["finding_ids"][0]))
    _mark_recurrence(findings, inputs["previous"])
    report_id = inputs["report_id"]
    sections = _sections(inputs, entries, findings, discarded, as_of, previous_version)
    report = {"format": "ptaas-report/1", "report_id": report_id,
              "engagement_id": inputs["engagement_id"], "as_of": as_of, "audit_seq": seq,
              "audit_hash": entries[-1]["hash"], "inputs": inputs["inputs_ref"],
              "generator_version": GENERATOR_VERSION,
              "findings": findings, "sections": sections}
    markdown = render_markdown(report)
    try:
        SensitiveData.check(report)
        SensitiveData.check(markdown, "markdown")
    except SensitiveData as exc:
        raise ReportError("sensitive_data", exc.where, report_id) from exc
    if has_jargon(json.dumps(sections[0]["content"], ensure_ascii=False)):
        raise ReportError("sensitive_data", "el resumen ejecutivo tiene jerga técnica", report_id)
    return report, markdown


def _mark_recurrence(findings: list[dict[str, Any]], previous: list[dict[str, Any]]) -> None:
    for f in findings:
        seen = next((p for p in previous if f["fingerprint"] in p["fingerprints"]), None)
        f["recurrence"] = None if not previous else (
            {"status": "new"} if seen is None else
            {"status": "recurring", "engagement": seen["engagement"],
             "report_id": seen["report_id"]})


def _changes(findings: list[dict[str, Any]],
             previous_version: dict[str, Any] | None) -> dict[str, Any] | None:
    if previous_version is None:
        return None
    old = {f["fingerprint"]: f for f in previous_version["findings"]}
    new = {f["fingerprint"]: f for f in findings}
    modified = []
    for fp in sorted(set(old) & set(new)):
        fields = [k for k in DIFF_FIELDS if old[fp].get(k) != new[fp].get(k)]
        if fields:
            modified.append({"fingerprint": fp, "fields": fields})
    return {"added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new)),
            "modified": modified}


def _counts(findings: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out = {s: {"validated": 0, "not_validated": 0} for s in SEVERITIES}
    for f in findings:
        out[f["severity"]][f["validation"]["status"]] += 1
    return out


def _posture(findings: list[dict[str, Any]]) -> str:
    sev = {f["severity"] for f in findings}
    return ("crítica" if "Critical" in sev else "alta" if "High" in sev
            else "media" if "Medium" in sev else "baja")


def _sections(inputs: dict[str, Any], entries: list[Entry], findings: list[dict[str, Any]],
              discarded: list[dict[str, Any]], as_of: str,
              previous_version: dict[str, Any] | None) -> list[dict[str, Any]]:
    counts = _counts(findings)
    high_unvalidated = [f for f in findings if f["manual_check"]]
    top = findings[:3]
    roe = inputs["roe"]
    results = {r.value: 0 for r in Result}
    for e in entries:
        results[e["result"]] = results.get(e["result"], 0) + 1
    recon_ok = sum(1 for e in entries if e["phase"] == "recon" and e["result"] == "OK")
    previous = inputs["previous"]
    content: dict[str, Any] = {
        "executive_summary": {
            "posture": _posture(findings),
            "counts": counts,
            "top": [{"title": f["title"], "impact": f["business_impact"]} for f in top],
            "recommendations": [first_sentence(f["remediation"]) for f in top],
            "unvalidated_high": len(high_unvalidated),
            "text": (f"La postura general de seguridad es {_posture(findings)}. Se informan "
                     f"{len(findings)} hallazgos; {sum(c['validated'] for c in counts.values())}"
                     " se confirmaron en un entorno aislado. "
                     + (f"{len(high_unvalidated)} hallazgos de severidad alta o crítica no "
                        "pudieron confirmarse y requieren verificación manual."
                        if high_unvalidated else
                        "No quedan hallazgos de severidad alta o crítica sin confirmar.")),
        },
        "introduction": {
            "scope": roe, "methodology": METHODOLOGY,
            "note": "Laboratorio propio y aislado; solo objetivos autorizados por el RoE.",
        },
        "information_gathering": {"assets": inputs["assets"], "recon_ok_records": recon_ok},
        "vulnerability_assessment": {"findings": [f["fingerprint"] for f in findings]},
        "sandbox_confirmation": {
            "catalog_version": inputs["poc_catalog_version"],
            "findings": [{"fingerprint": f["fingerprint"], "status": f["validation"]["status"],
                          "text": f["validation"]["text"], "attempts": f["attempts"]}
                         for f in findings]},
        "post_exploitation": {
            "text": "Fuera del alcance: no se realiza explotación. La validación se limita a "
                    "verificaciones inertes del catálogo, en sandbox y con aprobación humana."},
        "risk_exposure": {
            "counts": counts,
            "unvalidated_high": [{"fingerprint": f["fingerprint"], "severity": f["severity"],
                                  "reason": f["validation"]["text"]}
                                 for f in high_unvalidated]},
        "conclusion": {
            "text": (f"Postura {_posture(findings)}: {len(findings)} hallazgos, "
                     f"{len(high_unvalidated)} de severidad alta o crítica sin confirmar. "
                     "Se recomienda corregir primero los de mayor prioridad y volver a "
                     "evaluar.")},
        "annex_audit": {
            "audit_seq": len(entries), "audit_hash": entries[-1]["hash"], "as_of": as_of,
            "results": dict(sorted(results.items())),
            "verify": f"python -m harness.audit verify <bitácora de {inputs['engagement_id']}>"},
        "annex_evidence": {"refs": sorted({r for f in findings for r in f["evidence"]})},
        "annex_discarded": {"findings": discarded},
        "annex_disclosure": {"advisories": [_advisory(f, entries, inputs) for f in findings]},
        "annex_reproducibility": {
            "inputs": inputs["inputs_ref"],
            "hashes": {"report_catalog": inputs["catalog"]["sha256"],
                       "feeds_manifest": inputs["feeds"].get("manifest_sha256"),
                       "policy": inputs["policy_sha256"]},
            "poc_catalog_version": inputs["poc_catalog_version"],
            "generator_version": GENERATOR_VERSION,
            "supersedes": inputs["supersedes"],
            "changes": _changes(findings, previous_version),
            "previous": [{"engagement": p["engagement"], "report_id": p["report_id"],
                          "sha256": p["sha256"]} for p in previous],
            "not_observed": sorted({fp for p in previous for fp in p["fingerprints"]}
                                   - {f["fingerprint"] for f in findings}),
            "not_observed_note": "No observado no significa corregido.",
            "reproduce": f"python -m harness.reporting reproduce --engagement "
                         f"{inputs['engagement_id']} --report {inputs['report_id']}"},
    }
    return [{"id": sid, "key": key, "title": title, "content": content[key]}
            for sid, key, title in SECTIONS]


def _advisory(f: dict[str, Any], entries: list[Entry], inputs: dict[str, Any]) -> dict[str, Any]:
    analysis = next((e for e in entries if e["phase"] == "analyze" and e["result"] == "OK"
                     and e["target"] == f["host"]), None)
    return {
        "id": f["fingerprint"], "title": f["title"],
        "product": f["technologies"], "description": f["technical_description"],
        "impact": f["business_impact"],
        "severity": {"vector": f["cvss_v4_vector"], "score": f["cvss_v4_score"],
                     "label": f["severity"]},
        "validation": f["validation"]["text"], "remediation": f["remediation"],
        "references": f["references"],
        "timeline": {"analysis": None if analysis is None else _ts(analysis["ts"]),
                     "first_validation": f["attempts"][0]["at"] if f["attempts"] else None,
                     "report": inputs["report_id"]},
        "disclosure_status": "not_applicable_lab",
        "disclosure_note": "Objetivo intencionalmente vulnerable del laboratorio: no se "
                           "notifica al fabricante.",
        "contact": "equipo de divulgación del servicio",
    }


# ---- markdown (derivado del JSON) ----------------------------------------------------------

def _kv(items: Iterable[tuple[str, Any]]) -> list[str]:
    return [f"- **{k}:** {v}" for k, v in items]


def render_markdown(report: dict[str, Any]) -> str:
    by_fp = {f["fingerprint"]: f for f in report["findings"]}
    lines = [f"**Informe de pentest — {report['engagement_id']} ({report['report_id']})**", "",
             f"Estado de la bitácora al registro {report['audit_seq']} ({report['as_of']}).", ""]
    for s in report["sections"]:
        lines += [f"# {s['id']}. {s['title']}", ""]
        c = s["content"]
        key = s["key"]
        if key == "executive_summary":
            lines += [c["text"], "", "| Severidad | Validados | No validados |", "|---|---|---|"]
            lines += [f"| {sev} | {n['validated']} | {n['not_validated']} |"
                      for sev, n in c["counts"].items()]
            lines += ["", "Hallazgos principales:", ""]
            lines += [f"- {t['title']}: {t['impact']}" for t in c["top"]]
            lines += ["", "Recomendaciones:", ""] + [f"- {r}" for r in c["recommendations"]]
        elif key == "introduction":
            sc = c["scope"]
            lines += _kv([("CIDR", ", ".join(sc["cidrs"])), ("Dominios", ", ".join(sc["domains"])),
                          ("Exclusiones", ", ".join(sc["exclusions"]) or "ninguna"),
                          ("Ventana (UTC)", f"{sc['window_start']} a {sc['window_end']}"),
                          ("RoE (SHA-256)", sc["roe_sha256"]), ("Aprobó", sc["approver_role"]),
                          ("Metodología", ", ".join(c["methodology"]))])
            lines += ["", c["note"]]
        elif key == "information_gathering":
            lines += [f"Registros OK de relevamiento en la bitácora: {c['recon_ok_records']}.", ""]
            lines += [f"- {a['host']}: puertos {', '.join(map(str, a['ports'])) or '-'}; "
                      f"tecnologías {', '.join(a['technologies']) or '-'}" for a in c["assets"]]
        elif key == "vulnerability_assessment":
            for fp in c["findings"]:
                lines += _finding_md(by_fp[fp])
        elif key == "sandbox_confirmation":
            lines += [f"Catálogo de verificaciones: {c['catalog_version']}.", ""]
            for f in c["findings"]:
                lines.append(f"- {f['fingerprint']}: {f['text']}")
                lines += [f"  - intento {a['finding_id']} #{a['seq']} ({a['at']}): "
                          f"{a['outcome']} {a['result'] or '-'}, {a['poc_id'] or '-'}, "
                          f"{a['evidence'] or 'sin evidencia'}" for a in f["attempts"]]
        elif key in ("post_exploitation", "conclusion"):
            lines.append(c["text"])
        elif key == "risk_exposure":
            lines += [f"- {sev}: {n['validated']} validados, {n['not_validated']} no validados"
                      for sev, n in c["counts"].items()]
            lines += ["", "Severidad alta o crítica sin validar:", ""]
            lines += [f"- {u['fingerprint']} ({u['severity']}): {u['reason']}"
                      for u in c["unvalidated_high"]] or ["- ninguno"]
        elif key == "annex_audit":
            lines += _kv([("Registro", c["audit_seq"]), ("Hash", c["audit_hash"]),
                          ("Al", c["as_of"]), ("Verificación", f"`{c['verify']}`")])
            lines += [f"- {k}: {v}" for k, v in c["results"].items()]
        elif key == "annex_evidence":
            lines += [f"- {r}" for r in c["refs"]] or ["- ninguna"]
        elif key == "annex_discarded":
            lines += [f"- {d['fingerprint']} ({d['host']}): "
                      f"{', '.join(d['false_positive_ids']) or 'descartado por el análisis'}"
                      for d in c["findings"]] or ["- ninguno"]
        elif key == "annex_disclosure":
            for a in c["advisories"]:
                lines += [f"## {a['id']}: {a['title']}", ""]
                lines += _kv([("Producto", ", ".join(a["product"]) or "-"),
                              ("Severidad", (f"{a['severity']['label']} "
                                            f"{a['severity']['score']} ({a['severity']['vector']})")),
                              ("Validación", a["validation"]), ("Remediación", a["remediation"]),
                              ("Referencias", ", ".join(a["references"])),
                              ("Línea de tiempo", (f"análisis {a['timeline']['analysis'] or '-'}, "
                                                  f"validación "
                                                  f"{a['timeline']['first_validation'] or '-'}, "
                                                  f"informe {a['timeline']['report']}")),
                              ("Estado de divulgación", (f"{a['disclosure_status']}: "
                                                        f"{a['disclosure_note']}")),
                              ("Contacto", a["contact"])])
                lines.append("")
        elif key == "annex_reproducibility":
            lines += _kv([("Entradas", c["inputs"]), ("Generador", c["generator_version"]),
                          ("Catálogo de verificaciones", c["poc_catalog_version"]),
                          ("Reemplaza a", "-" if c["supersedes"] is None else
                           f"{c['supersedes']['report_id']} ({c['supersedes']['sha256']})"),
                          ("Reproducir", f"`{c['reproduce']}`")])
            lines += [f"- {k}: {v}" for k, v in c["hashes"].items()]
            if c["changes"] is not None:
                ch = c["changes"]
                lines += [f"- agregados: {', '.join(ch['added']) or '-'}",
                          f"- quitados: {', '.join(ch['removed']) or '-'}"]
                lines += [f"- modificado {m['fingerprint']}: {', '.join(m['fields'])}"
                          for m in ch["modified"]]
            if c["previous"]:
                lines += [(f"- no observados ({c['not_observed_note']}): "
                          f"{', '.join(c['not_observed']) or '-'}")]
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _finding_md(f: dict[str, Any]) -> list[str]:
    v = f["validation"]
    status = ("Validado en sandbox" if v["status"] == "validated"
              else f"No validado: {v['text']}")
    if v["status"] != "validated" and f["analysis_status"] == "confirmed":
        status = f"confirmado por análisis, no validado en sandbox ({v['text']})"
    lines = [f"## {f['title']} ({f['severity']})", ""]
    if f["manual_check"]:
        lines += [f"**No validado: requiere verificación manual** ({v['text']}).", ""]
    rec = f["recurrence"]
    lines += _kv([
        ("Huella", f["fingerprint"]), ("Host", f["host"]),
        ("Identificadores", ", ".join(x for x in (f["cve"], f["cwe"]) if x)),
        ("CVSS v4.0", f"{f['cvss_v4_score']} {f['severity']} ({f['cvss_v4_vector']})"),
        ("EPSS", f["epss"]["text"]),
        ("Prioridad", f["priority"] or "sin puntaje"),
        ("Estado", status),
        ("Descripción", f["technical_description"]),
        ("Remediación", f["remediation"]),
        ("Referencias", ", ".join(f["references"])),
    ])
    if f["feed_cvss"] and f["feed_cvss"]["differs"]:
        lines.append(f"- **Puntaje del feed distinto:** {f['feed_cvss']['score']} "
                     f"(CVSS {f['feed_cvss']['version']}); manda el del vector curado.")
    if rec is not None:
        lines.append(f"- **Recurrencia:** {rec['status']}"
                     + (f" ({rec['engagement']}/{rec['report_id']})"
                        if rec["status"] == "recurring" else ""))
    lines += [f"- Observación {o['tool']} {o['check']} en {o['url']} ({o['risk']}, "
              f"{o['confidence']}): {o['evidence'] or '-'}" for o in f["observations"]]
    lines += [f"- Evidencia: {r}" for r in f["evidence"]]
    lines.append("")
    return lines


# ---- generación: junta entradas, valida, escribe y registra --------------------------------

@dataclass
class ReportContext:
    engagement: Engagement
    roe: RoE
    audit: AuditSink
    state_dir: Path
    store: FindingStore
    catalog: ReportCatalog
    graph: AssetGraph | None = None
    approvals: ApprovalStore | None = None
    previous: list[PreviousReport] = field(default_factory=list)


@dataclass(frozen=True)
class GeneratedReport:
    report_id: str
    path: Path
    markdown_path: Path
    ref: str


def _lab_targets() -> dict[str, list[str]]:
    import yaml
    targets = yaml.safe_load(PROFILES.read_text(encoding="utf-8"))["targets"]
    return {"domains": sorted(d.lower() for d in targets["lab_only_domains"]),
            "cidrs": sorted(targets["lab_only_cidrs"])}


def _roe_summary(roe: RoE) -> dict[str, Any]:
    """Alcance para el informe: sin contactos de emergencia ni nombres (D5)."""
    return {"cidrs": sorted(roe.cidrs), "domains": sorted(roe.domains),
            "exclusions": sorted(roe.excluded),
            "window_start": roe.window_start.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_end": roe.window_end.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "roe_sha256": roe.digest, "approver_role": "Reviewer del engagement"}


def _assets(graph: AssetGraph | None, hosts: set[str]) -> list[dict[str, Any]]:
    if graph is None:
        return []
    out: dict[str, dict[str, Any]] = {}
    for a in graph.assets(in_scope=True):
        h = host_of(a)
        if h not in hosts:
            continue
        info = out.setdefault(h, {"host": h, "ports": set(), "technologies": set()})
        if a.type == "http_service":
            from urllib.parse import urlsplit
            info["ports"].add(urlsplit(a.address).port or 80)
        info["technologies"].update(redact(t) for t, _ in graph.tech_sources(a.id))
    return [{"host": h, "ports": sorted(i["ports"]), "technologies": sorted(i["technologies"])}
            for h, i in sorted(out.items())]


def _feeds() -> dict[str, Any]:
    try:
        raw = FEEDS_MANIFEST.read_bytes()
        epss = json.loads(raw)["files"]["epss.csv"]["retrieved_at"][:10]
    except (OSError, KeyError, ValueError):
        return {"epss_date": None, "manifest_sha256": None}
    return {"epss_date": epss, "manifest_sha256": _sha(raw)}


def _fail(ctx: ReportContext, reason: str, subject: str) -> None:
    ctx.audit.record_control(ctx.roe.engagement_id, AGENT, REPORT_FAILED_ACTION,
                             ctx.roe.engagement_id, Result.ABORTED, reason, subject=subject)


def generate_report(ctx: ReportContext, vulns: list[PrioritizedVuln],
                    candidates: list[CandidateFinding]) -> GeneratedReport:
    """Genera la próxima versión. Ante cualquier fallo no escribe ningún archivo."""
    eng = ctx.roe.engagement_id
    entries = [e for e in ctx.audit.entries if e.get("engagement") == eng]
    n = 1 + len(_generated_refs(entries))
    report_id = f"report-v{n}"
    if ctx.engagement.state == State.DELIVERED:
        _fail(ctx, "engagement_delivered", report_id)
        raise ReportError("engagement_delivered", "el engagement ya se entregó", report_id)
    if ctx.engagement.state != State.REPORT:
        _fail(ctx, "engagement_not_in_report", report_id)
        raise ReportError("engagement_not_in_report", f"estado {ctx.engagement.state.value}",
                          report_id)
    ctx.audit.verify_integrity()                     # AuditIntegrityError: no se escribe nada
    entries = [e for e in ctx.audit.entries if e.get("engagement") == eng]
    out_dir = ctx.state_dir / "reports" / eng
    paths = [out_dir / f"{name}-v{n}.{ext}" for name, ext in
             (("inputs", "json"), ("report", "json"), ("report", "md"))]
    if any(p.exists() for p in paths):
        raise FileExistsError(f"{report_id}: ya hay archivos de esa versión y no se sobrescriben")

    refs = _generated_refs(entries)
    supersedes = None
    previous_version = None
    if n > 1:
        prev_ref = refs[f"report-v{n - 1}"]
        if not verify_evidence(ctx.state_dir, prev_ref):
            raise ReportError("evidence_mismatch", f"la versión anterior {prev_ref} no verifica",
                              f"report-v{n - 1}")
        previous_version = json.loads((ctx.state_dir / prev_ref.split("#")[0]).read_bytes())
        supersedes = {"report_id": f"report-v{n - 1}", "sha256": prev_ref.split("=", 1)[1]}

    hosts = {c.host for c in candidates}
    observations = [asdict(o) for o in ctx.store.observations()]
    used = {}
    for c in candidates:
        for key in (c.cve, c.cwe):
            if key and key in ctx.catalog.raw:
                used[key] = ctx.catalog.raw[key]
    inputs = {
        "format": "ptaas-report-inputs/1", "engagement_id": eng, "report_id": report_id,
        "audit_seq": len(entries), "roe": _roe_summary(ctx.roe), "lab": _lab_targets(),
        "vulns": [{**asdict(v), "evidence_refs": list(v.evidence_refs)} for v in vulns],
        "candidates": [asdict(c) for c in candidates], "observations": observations,
        "assets": _assets(ctx.graph, hosts),
        "catalog": {"sha256": ctx.catalog.sha256, "entries": used},
        "poc_catalog_version": poc_catalog_version(),
        "feeds": _feeds(), "policy_sha256": _sha(POLICY.read_bytes()),
        "supersedes": supersedes,
        "previous": [asdict(p) | {"fingerprints": list(p.fingerprints)} for p in ctx.previous],
    }
    inputs_raw = canonical(inputs)
    inputs_rel = f"reports/{eng}/inputs-v{n}.json"
    inputs["inputs_ref"] = f"{inputs_rel}#sha256={_sha(inputs_raw)}"

    try:
        _check_closures(ctx, vulns, entries)
        report, markdown = build(inputs, entries, ctx.state_dir, previous_version)
    except MissingField as exc:
        for fid, name in exc.missing:             # los otros nombres explican por qué
            if name in FIELD_REASONS:
                _fail(ctx, FIELD_REASONS[name], fid)
        raise
    except ReportError as exc:
        _fail(ctx, exc.reason, exc.subject or report_id)
        raise

    out_dir.mkdir(parents=True, exist_ok=True)
    report_raw = canonical(report)
    for path, data in ((paths[0], inputs_raw), (paths[1], report_raw),
                       (paths[2], markdown.encode("utf-8"))):
        with path.open("xb") as fh:
            fh.write(data)
    ref = f"reports/{eng}/report-v{n}.json#sha256={_sha(report_raw)}"
    ctx.audit.record_control(eng, AGENT, REPORT_GENERATED_ACTION, eng, Result.OK,
                             evidence=ref, subject=report_id)
    return GeneratedReport(report_id, paths[1], paths[2], ref)


def _check_closures(ctx: ReportContext, vulns: list[PrioritizedVuln],
                    entries: list[Entry]) -> None:
    """Si el registro dice `validated` y la bitácora no, no se afirma nada (D6)."""
    if ctx.approvals is None:
        return
    for v in vulns:
        closure = ctx.approvals.closure(v.finding_id)
        if closure is not None and closure.outcome == "validated":
            status = validation_of({v.finding_id}, entries, ctx.state_dir)["status"]
            if status != "validated":
                raise ReportError("validation_mismatch",
                                  f"{v.finding_id}: el registro dice validado y la bitácora no",
                                  v.finding_id)


# ---- reproducción --------------------------------------------------------------------------

def reproduce(engagement_id: str, report_id: str, state_dir: Path | str,
              audit_dir: Path | str) -> tuple[bool, str]:
    """(True, "") si la versión se reconstruye byte a byte; si no, (False, qué no coincide)."""
    state = Path(state_dir)
    audit_path = Path(audit_dir) / f"{engagement_id}.sqlite3"
    error = verify_file(audit_path) if audit_path.is_file() else "no hay bitácora"
    if error is not None:
        return False, f"bitácora: {error}"
    log = SqliteAuditLog.open(engagement_id, audit_dir)
    try:
        entries = [e for e in log.entries if e.get("engagement") == engagement_id]
    finally:
        log.close()
    refs = _generated_refs(entries)
    ref = refs.get(report_id)
    if ref is None:
        return False, f"{report_id}: no hay report.generated en la bitácora"
    if not verify_evidence(state, ref):
        return False, f"{ref}: el informe no coincide con la bitácora"
    report_raw = (state / ref.split("#")[0]).read_bytes()
    report = json.loads(report_raw)
    inputs_ref = report["inputs"]
    if not verify_evidence(state, inputs_ref):
        return False, f"{inputs_ref}: el snapshot de entradas no coincide"
    inputs = json.loads((state / inputs_ref.split("#")[0]).read_bytes())
    inputs["inputs_ref"] = inputs_ref
    previous_version = None
    if inputs["supersedes"] is not None:
        prev_ref = refs.get(inputs["supersedes"]["report_id"], "")
        if not verify_evidence(state, prev_ref) or \
                prev_ref.split("=", 1)[1] != inputs["supersedes"]["sha256"]:
            return False, f"{inputs['supersedes']['report_id']}: la versión anterior no coincide"
        previous_version = json.loads((state / prev_ref.split("#")[0]).read_bytes())
    try:
        again, markdown = build(inputs, entries, state, previous_version)
    except ReportError as exc:
        return False, str(exc)
    again_raw = canonical(again)
    if again_raw != report_raw:
        first = next((k for k in sorted(set(report) | set(again))
                      if report.get(k) != again.get(k)), "?")
        return False, f"el JSON no coincide (primer campo distinto: {first})"
    md_path = state / "reports" / engagement_id / f"{report_id}.md"
    if not md_path.is_file() or md_path.read_text(encoding="utf-8") != markdown:
        return False, "el markdown no coincide"
    return True, ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m harness.reporting")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("reproduce", help="reconstruye una versión y la compara byte a byte")
    r.add_argument("--engagement", required=True)
    r.add_argument("--report", required=True)
    r.add_argument("--state-dir", default="state")
    r.add_argument("--audit-dir", default="audit")
    args = p.parse_args(argv)
    if not _ENGAGEMENT_RE.match(args.engagement) or not REPORT_ID_RE.match(args.report):
        print("engagement o informe inválido", file=sys.stderr)
        return 2
    same, why = reproduce(args.engagement, args.report, args.state_dir, args.audit_dir)
    print(f"OK: {args.report} se reproduce byte a byte" if same else f"NO COINCIDE: {why}")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
