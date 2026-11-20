"""Armado de escenarios del informe (change 007): bitácora, hallazgos, evidencia y tabla curada."""
from __future__ import annotations

import copy
from datetime import UTC, datetime

from demo.checkpoint1 import prepare_roe
from demo.pipeline import ROE_TEMPLATE
from harness.analysis import FindingStore, Observation
from harness.approvals import ApprovalStore
from harness.audit import SqliteAuditLog
from harness.contracts import Result
from harness.engagement import Engagement, State
from harness.evidence import build_evidence, write_evidence
from harness.report_catalog import ReportCatalog
from harness.reporting import ReportContext, generate_report
from harness.roe import parse_roe
from harness.schemas import CandidateFinding, PrioritizedVuln

ENG = "eng-1"
HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"      # 8.7 High
MEDIUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"    # 5.1 Medium
LOW = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N"       # 2.1 Low
CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"  # 9.3 Critical


def entry(vector=MEDIUM, **over):
    base = {"title": "Falta la política de seguridad de contenido",
            "technical_description": "La respuesta no envía Content-Security-Policy.",
            "business_impact": "Un atacante tiene más facilidad para robar sesiones.",
            "remediation": "Configurar una política restrictiva. Probarla primero.",
            "references": ["WSTG-CONF-12"], "cvss_v4_vector": vector,
            "author": "ana", "reviewer": "beto", "date": "2026-11-20"}
    return base | over


ENTRIES = {
    "CWE-693": entry(LOW),
    "CWE-1021": entry(MEDIUM, title="La página se puede mostrar dentro de otro sitio"),
    "CWE-22": entry(HIGH, title="Lectura de archivos fuera del sitio"),
    "CVE-2021-41773": entry(CRITICAL, title="Recorrido de rutas en el servidor web"),
}


def in_state(state):
    e = Engagement(roe_valid=True)
    e.approve("first_active_action")
    e.approve("before_validate")
    while e.state != state:
        e.advance()
    return e


class Lab:
    def __init__(self, tmp_path, entries=None, state=State.REPORT, eng=ENG):
        self.eng = eng
        self.state_dir, self.audit_dir = tmp_path / "state", tmp_path / "audit"
        self.audit = SqliteAuditLog.open(eng, self.audit_dir)
        self.audit.record_control(eng, "scope-guard", "token.issue", "report", Result.OK)
        self.store = FindingStore.open(eng, self.state_dir)
        self.approvals = ApprovalStore.open(eng, self.state_dir)
        self.entries = copy.deepcopy(ENTRIES if entries is None else entries)
        self.engagement = in_state(state)
        self.roe = parse_roe(prepare_roe(eng, datetime(2026, 11, 20, 12, tzinfo=UTC),
                                         ROE_TEMPLATE))
        self.vulns, self.candidates = [], []
        self.previous = []

    # -- hallazgos --------------------------------------------------------------------------
    def finding(self, fid, cwe="CWE-693", host="dvwa.lab.test", status="confirmed", cve=None,
                priority=None, epss=None, asset=None, cvss=None, feed_stale=False,
                rationale="r"):
        score, version = cvss if cvss else (None, None)
        self.candidates.append(CandidateFinding(
            id=fid, asset_id=asset or f"asset-{host}", cwe=cwe, cve=cve, epss=epss,
            evidence_refs=[f"zap:1@http://{host}/"], host=host, cvss_score=score,
            cvss_version=version, feed_stale=feed_stale))
        self.vulns.append(PrioritizedVuln(finding_id=fid, status=status, rationale=rationale,
                                          priority=priority))
        return fid

    def observe(self, host, cwe, url, evidence="", tool="zap"):
        self.store.add(Observation(host, 2, tool, "10038", cwe, url, "high", "Medium", evidence))

    # -- bitácora del loop C ------------------------------------------------------------------
    def attempt(self, fid, n=1, result="validated", truncated=False, ok=True):
        doc = build_evidence(finding_id=fid, attempt=n, poc_id="POC-CSP-001", poc_version="1.0.0",
                             catalog_version="0.2.0", parameters={"base_url": "http://x"},
                             sandbox_id=f"ptaas-sbx-{'ab' * 16}", request=None, record=None,
                             evaluator="header_missing_csp", canary=None, result=result,
                             detail="d", truncated=truncated)
        ref = write_evidence(self.state_dir, self.eng, fid, n, doc)
        self.audit.record_control(self.eng, "validation-orchestrator", "validation.attempt", fid,
                                  Result.OK if ok else Result.ABORTED,
                                  None if ok else "sandbox_error", ref, fid)
        return ref

    def closed(self, fid, reason):
        self.audit.record_control(self.eng, "validation-orchestrator", "validation.closed", fid,
                                  Result.ABORTED, reason, subject=fid)

    def control(self, action):
        return [e for e in self.audit.entries if e["action"] == action]

    # -- generación ----------------------------------------------------------------------------
    def ctx(self):
        return ReportContext(engagement=self.engagement, roe=self.roe, audit=self.audit,
                             state_dir=self.state_dir, store=self.store,
                             catalog=ReportCatalog.from_entries(self.entries, "c" * 64),
                             approvals=self.approvals, previous=self.previous)

    def generate(self):
        return generate_report(self.ctx(), self.vulns, self.candidates)

    def reports_dir(self):
        return self.state_dir / "reports" / self.eng

    def files(self):
        d = self.reports_dir()
        return sorted(p.name for p in d.iterdir()) if d.exists() else []
