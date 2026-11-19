"""Loop B (análisis) del change 005: determinista, por candidato y con estado persistido.

Por cada host se sigue un plan fijo: primero `nuclei.safe_templates` y después
`zap.baseline_scan`, cada uno UNA vez por host y por engagement (D11). Lo que observan las
herramientas queda en un almacén append-only. Cada candidato se resuelve con reglas fijas:

- `confirmed`: evidencia de análisis de confianza alta en una URL sin contradicción;
- `discarded`: solo por una entrada aprobada de la lista de falsos positivos (D10);
- `inconclusive`: todo lo demás, incluida la evidencia que es solo de versión (D4) y las
  contradicciones entre verificaciones equivalentes (D8), que además piden revisión humana.
"""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from harness.contracts import (
    Action,
    AuditIntegrityError,
    Harness,
    KillSwitchEngaged,
    Phase,
    Result,
    ScopeToken,
    ScopeViolation,
)
from harness.correlate import candidate_id
from harness.engagement import Engagement, State
from harness.loops import decide_detection
from harness.policy_loader import load_policy
from harness.schemas import CandidateFinding, PrioritizedVuln, SchemaGate, dedupe, priority_score

ROOT = Path(__file__).resolve().parent.parent
EQUIVALENCES = ROOT / "data" / "check_equivalences.yaml"
FALSE_POSITIVES = ROOT / "data" / "false_positives.yaml"
AGENT = "analysis-orchestrator"
PLAN = ("nuclei.safe_templates", "zap.baseline_scan")
_FATAL = frozenset({"token_expired", "token_invalid", "token_revoked"})
_NUCLEI_RISK = {"info": "Low", "low": "Low", "medium": "Medium", "high": "High",
                "critical": "High"}
_ZAP_CONFIDENCE = {"Confirmed": "high", "High": "high", "Medium": "medium", "Low": "low"}
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_FP_FIELDS = ("id", "tool", "check", "url_pattern", "reason", "author", "reviewer", "date")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
  host TEXT NOT NULL, step INTEGER NOT NULL, tool TEXT NOT NULL, check_id TEXT NOT NULL,
  cwe TEXT NOT NULL, url TEXT NOT NULL, confidence TEXT NOT NULL, risk TEXT NOT NULL,
  evidence TEXT NOT NULL, UNIQUE (host, tool, check_id, url));
CREATE TABLE IF NOT EXISTS events (
  kind TEXT NOT NULL CHECK (kind IN ('step_done','tool_disabled','covered')),
  value TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS observations_no_update BEFORE UPDATE ON observations
BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS observations_no_delete BEFORE DELETE ON observations
BEGIN SELECT RAISE(ABORT, 'append-only: DELETE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'append-only: DELETE prohibido'); END;
"""


@dataclass(frozen=True)
class Observation:
    host: str
    step: int                 # 1 = nuclei, 2 = ZAP (posición en PLAN)
    tool: str                 # nuclei | zap
    check_id: str             # template-id o pluginId
    cwe: str
    url: str
    confidence: str           # low | medium | high
    risk: str                 # Informational | Low | Medium | High
    evidence: str

    @property
    def ref(self) -> str:
        return f"{self.tool}:{self.check_id}@{self.url}"


class FindingStore:
    """Estado del loop B, append-only: `state/<engagement>.findings.sqlite3`."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._con = sqlite3.connect(path, isolation_level=None)
        self._con.executescript(_SCHEMA)

    @classmethod
    def open(cls, engagement_id: str, base_dir: Path | str = "state") -> FindingStore:
        if not _ENGAGEMENT_RE.match(engagement_id):
            raise ValueError(f"engagement_id inválido: {engagement_id!r}")
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        return cls(base / f"{engagement_id}.findings.sqlite3")

    def close(self) -> None:
        self._con.close()

    def add(self, o: Observation) -> bool:
        cur = self._con.execute(
            "INSERT OR IGNORE INTO observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (o.host, o.step, o.tool, o.check_id, o.cwe, o.url, o.confidence, o.risk,
             o.evidence))
        return cur.rowcount == 1

    def observations(self, host: str | None = None) -> list[Observation]:
        rows = self._con.execute("SELECT * FROM observations ORDER BY rowid").fetchall()
        found = [Observation(*r) for r in rows]
        return [o for o in found if host is None or o.host == host]

    def _event(self, kind: str, value: str) -> None:
        self._con.execute("INSERT INTO events VALUES (?, ?)", (kind, value))

    def mark_step(self, host: str, capability: str) -> None:
        self._event("step_done", f"{host}|{capability}")

    def steps_done(self) -> set[str]:
        return {str(r[0]) for r in self._con.execute(
            "SELECT value FROM events WHERE kind = 'step_done'")}

    def mark_covered(self, host: str, tool: str, check_id: str) -> None:
        """La verificación corrió sobre el host (sirve para distinguir silencio de no corrió)."""
        self._event("covered", f"{host}|{tool}|{check_id}")

    def covered(self, host: str, tool: str) -> set[str]:
        prefix = f"{host}|{tool}|"
        return {str(r[0])[len(prefix):] for r in self._con.execute(
            "SELECT value FROM events WHERE kind = 'covered'") if str(r[0]).startswith(prefix)}

    def mark_disabled(self, capability: str) -> None:
        self._event("tool_disabled", capability)

    def disabled(self) -> set[str]:
        return {str(r[0]) for r in self._con.execute(
            "SELECT value FROM events WHERE kind = 'tool_disabled'")}


# -- tablas curadas --------------------------------------------------------------------
def load_equivalences(path: Path = EQUIVALENCES) -> dict[tuple[str, str], tuple[str, str]]:
    """(herramienta, verificación) → la verificación equivalente de la otra herramienta."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[tuple[str, str], tuple[str, str]] = {}
    for e in data.get("equivalences") or []:
        z, n = ("zap", str(e["zap"])), ("nuclei", str(e["nuclei"]))
        out[z], out[n] = n, z
    return out


@dataclass(frozen=True)
class FalsePositive:
    id: str
    tool: str
    check: str
    url_pattern: re.Pattern[str]
    reason: str
    approved: bool


def load_false_positives(path: Path = FALSE_POSITIVES) -> list[FalsePositive]:
    """Lanza ValueError si una entrada está incompleta: la lista se revisa como un template."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for e in data.get("entries") or []:
        if not isinstance(e, dict) or any(not str(e.get(f) or "").strip() for f in _FP_FIELDS):
            raise ValueError(f"entrada de falso positivo incompleta: {e!r}")
        if {"cve", "cve_id"} & set(e) or e["tool"] not in ("zap", "nuclei"):
            raise ValueError(f"entrada de falso positivo inválida: {e['id']}")
        reviewer, author = str(e["reviewer"]).strip().lower(), str(e["author"]).strip().lower()
        out.append(FalsePositive(str(e["id"]), str(e["tool"]), str(e["check"]),
                                 re.compile(str(e["url_pattern"])), str(e["reason"]),
                                 approved=reviewer not in ("pendiente", author)))
    return out


# -- loop B -------------------------------------------------------------------------------
@dataclass
class AnalysisResult:
    vulns: list[PrioritizedVuln] = field(default_factory=list)
    candidates: list[CandidateFinding] = field(default_factory=list)
    reason: str = "ok"
    stop_reasons: dict[str, str] = field(default_factory=dict)


class _Abort(Exception):
    pass


class AnalysisLoop:
    def __init__(self, harness: Harness, token: ScopeToken, store: FindingStore, *,
                 engagement: Engagement, asset_of: Callable[[str], str],
                 criticality_of: Callable[[str], tuple[int, bool]] = lambda h: (3, True),
                 equivalences: dict[tuple[str, str], tuple[str, str]] | None = None,
                 false_positives: list[FalsePositive] | None = None,
                 max_iterations: int | None = None) -> None:
        if token.phase is not Phase.ANALYZE:
            raise ValueError("el análisis necesita un token de fase ANALYZE")
        self.harness, self.token, self.store = harness, token, store
        self.engagement = engagement
        self.asset_of, self.criticality_of = asset_of, criticality_of
        self.equivalences = load_equivalences() if equivalences is None else equivalences
        self.false_positives = (load_false_positives() if false_positives is None
                                else false_positives)
        limit = (max_iterations if max_iterations is not None
                 else load_policy()["limits"]["max_loop_iterations"]["detection"])
        if type(limit) is not int or limit < 1:
            raise ValueError("tope de iteraciones inválido")
        self.max_iterations = limit
        self._gates: dict[str, SchemaGate] = {}

    # -- ejecución ---------------------------------------------------------------------
    def run(self, candidates: list[CandidateFinding], hosts: list[str]) -> AnalysisResult:
        # nuclei y el spider de ZAP generan tráfico: sin el engagement en ANALYZE (al que se
        # llega pasando por el gate first_active_action) no se invoca nada (revisión 005, B3).
        if self.engagement.state != State.ANALYZE:
            return AnalysisResult(candidates=list(candidates),
                                  reason="engagement fuera de ANALYZE")
        all_hosts = sorted(set(hosts) | {c.host for c in candidates if c.host})
        reason = "ok"
        try:
            for host in all_hosts:
                for step, capability in enumerate(PLAN, start=1):
                    key = f"{host}|{capability}"
                    if key in self.store.steps_done() or capability in self.store.disabled():
                        continue
                    out = self._invoke(capability, host)
                    if out is not None:
                        self._observe(host, step, out)
                        self.store.mark_step(host, capability)
        except _Abort as exc:
            reason = f"abortado: {exc}"
        merged = dedupe([*candidates, *self._analysis_candidates(all_hosts)])
        result = AnalysisResult(candidates=merged, reason=reason)
        for c in merged:
            vuln, stop = self._resolve(c)
            result.vulns.append(vuln)
            result.stop_reasons[c.id] = stop
        result.vulns.sort(key=lambda v: (v.priority is None, -(v.priority or 0), v.finding_id))
        return result

    def _invoke(self, capability: str, host: str) -> dict[str, Any] | None:
        try:
            out = self.harness.invoke(AGENT, Action(capability, Phase.ANALYZE), host, self.token)
        except KillSwitchEngaged as exc:
            raise _Abort("kill switch") from exc
        except AuditIntegrityError as exc:
            raise _Abort("bitácora rota") from exc
        except ScopeViolation as exc:
            if exc.reason in _FATAL:
                raise _Abort(str(exc.reason)) from exc
            return None
        status = out.get("status")
        if status == "error":
            if out.get("error") != "adapter_error":
                self._control("tool.error", host, Result.ABORTED, str(out.get("error")))
            return None
        gate = self._gates.setdefault(capability, SchemaGate())
        if status == "invalid_output":
            self._control("tool.error", host, Result.ABORTED, "invalid_output")
            if gate.record(False) == "PENDING_HITL":
                self.store.mark_disabled(capability)
                self._control("tool.escalated", capability, Result.PENDING_HITL,
                              "invalid_output")
            return None
        if status == "PENDING_HITL":
            return None
        gate.record(True)
        return out

    def _control(self, action: str, target: str, result: Result, reason: str) -> None:
        self.harness.audit.record_control(self.token.engagement_id, AGENT, action, target,
                                          result, reason)

    def _observe(self, host: str, step: int, out: dict[str, Any]) -> None:
        if out.get("tool") == "nuclei":
            for f in out.get("findings") or []:
                risk = _NUCLEI_RISK.get(str(f.get("severity")), "Low")   # M7: un FP no la tapa
                self.store.add(Observation(host, step, "nuclei", f["template_id"], f["cwe"],
                                           f["url"], "high", risk, "; ".join(f["evidence"])))
            for t in out.get("templates_run") or []:
                self.store.mark_covered(host, "nuclei", str(t))
        elif out.get("tool") == "zap":
            for a in out.get("alerts") or []:
                conf = _ZAP_CONFIDENCE.get(a["confidence"])
                if conf is None:
                    continue                      # ZAP mismo lo marcó como falso positivo
                self.store.add(Observation(host, step, "zap", a["plugin_id"], a["cwe"],
                                           a["url"], conf, a["risk"], a["evidence"] or ""))

    def _analysis_candidates(self, hosts: list[str]) -> list[CandidateFinding]:
        out = []
        for host in hosts:
            by_cwe: dict[str, list[Observation]] = {}
            for o in self.store.observations(host):
                if o.cwe == "unknown" or o.risk == "Informational":
                    continue                      # observación, no candidato
                by_cwe.setdefault(o.cwe, []).append(o)
            for cwe, obs in sorted(by_cwe.items()):
                asset = self.asset_of(host)
                best = max(("low", "medium", "high").index(o.confidence) for o in obs)
                out.append(CandidateFinding(
                    id=candidate_id(asset, cwe), asset_id=asset, cwe=cwe,
                    evidence_refs=sorted({o.ref for o in obs}),
                    confidence=("low", "medium", "high")[best], host=host,
                    title=f"{cwe} en {host}"))
        return out

    # -- resolución ------------------------------------------------------------------------
    def _resolve(self, c: CandidateFinding) -> tuple[PrioritizedVuln, str]:
        # Un candidato por CVE no toma evidencia "por CWE": que ZAP vea que falta el CSP no
        # prueba un CVE de Apache con ese CWE. Sin una verificación atada al CVE (en el MVP no
        # hay), queda inconcluso hasta VALIDATE (revisión 005, B1). La evidencia por CWE ya
        # tiene su propio candidato.
        relevant = [] if c.cve else [o for o in self.store.observations(c.host)
                                     if c.cwe != "unknown" and o.cwe == c.cwe]
        history: list[int] = []
        status, rationale, review = "inconclusive", "", False
        decision_reason = "tope de iteraciones alcanzado"
        for i in range(1, self.max_iterations + 1):
            seen = [o for o in relevant if o.step <= i]
            history.append(len([o for o in relevant if o.step == i]))
            status, rationale, review = self._status(c, seen)
            decision = decide_detection(history, self.max_iterations,
                                        resolved=status in ("confirmed", "discarded"))
            if decision.decision == "stop":
                decision_reason = decision.reason
                break
        crit, default_crit = self.criticality_of(c.host)
        priority = (priority_score(c.cvss_score, c.epss, crit)
                    if c.cvss_score is not None else None)
        extra = (f" Prioridad {priority} con CVSS {c.cvss_version} {c.cvss_score}, EPSS "
                 f"{'sin dato' if c.epss is None else c.epss} y criticidad {crit}"
                 f"{' (valor por defecto)' if default_crit else ''}."
                 if priority is not None else " Sin puntaje: no hay CVSS.")
        refs = tuple(sorted(set(c.evidence_refs) | {o.ref for o in relevant}))
        return PrioritizedVuln(
            finding_id=c.id, status=status, rationale=f"{rationale}{extra} Loop B: "
            f"{decision_reason}.", evidence_refs=refs,
            cvss_v4_score=c.cvss_score if c.cvss_version == "4.0" else None,
            cvss_score=c.cvss_score, cvss_version=c.cvss_version, priority=priority,
            needs_review=review), decision_reason

    def _status(self, c: CandidateFinding, seen: list[Observation]) -> tuple[str, str, bool]:
        contradictions = self._contradictions(c.host, seen)
        if seen and c.cve is None and all(self._false_positive(o) for o in seen):
            ids = sorted({fp.id for o in seen if (fp := self._false_positive(o))})
            return ("discarded", f"Falso positivo conocido ({', '.join(ids)}).", False)
        strong = [o for o in seen if o.confidence == "high" and o.url not in contradictions]
        if contradictions:                       # la spec manda: inconcluso y a revisión (B4)
            pairs = "; ".join(f"{u}: {v}" for u, v in sorted(contradictions.items()))
            text = f"Sin confirmar. Contradicción entre verificaciones equivalentes ({pairs})."
            if strong:
                refs = ", ".join(sorted({o.ref for o in strong})[:3])
                text += (f" Hay evidencia fuerte en otras URL ({refs}), pero no se confirma "
                         "mientras haya una contradicción.")
            return ("inconclusive", f"{text} Requiere revisión humana.", True)
        if strong:
            tools = sorted({o.tool for o in strong})
            refs = ", ".join(sorted({o.ref for o in strong})[:3])
            return ("confirmed", f"Confirmado por {' y '.join(tools)} ({refs}).", False)
        if c.cve and not seen:
            text = ("Solo evidencia de versión: una versión sola no confirma (puede haber "
                    "backport). Se confirma en VALIDATE con el catálogo.")
            return ("inconclusive", text, False)
        if seen:
            return ("inconclusive", "Evidencia de análisis de confianza media o baja.", False)
        return ("inconclusive", "Ninguna herramienta aportó evidencia.", False)

    def _contradictions(self, host: str, seen: list[Observation]) -> dict[str, str]:
        """URL → descripción, cuando una verificación marcó y su equivalente la revisó y no."""
        all_obs = self.store.observations(host)
        zap_paths = {o.url for o in all_obs if o.tool == "zap"}     # ZAP visitó esas URL
        nuclei_ran = self.store.covered(host, "nuclei")
        out: dict[str, str] = {}
        for o in seen:
            other = self.equivalences.get((o.tool, o.check_id))
            if other is None:
                continue
            other_tool, other_check = other
            reported = any(x.tool == other_tool and x.check_id == other_check and x.url == o.url
                           for x in all_obs)
            covered = (o.url in zap_paths if other_tool == "zap" else
                       other_check in nuclei_ran and urlsplit(o.url).path == "/")
            if covered and not reported:
                out[o.url] = f"{o.tool} {o.check_id} sí, {other_tool} {other_check} no"
        return out

    def _false_positive(self, o: Observation) -> FalsePositive | None:
        if o.risk == "High":
            return None                            # el riesgo alto lo revisa una persona
        for fp in self.false_positives:
            if fp.approved and fp.tool == o.tool and fp.check == o.check_id \
                    and fp.url_pattern.search(o.url):
                return fp
        return None
