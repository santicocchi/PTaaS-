"""Armado de escenarios del informe (change 007): bitácora, hallazgos, evidencia y tabla curada."""
from __future__ import annotations

import copy
import time
from datetime import UTC, datetime

from demo.checkpoint1 import prepare_roe
from demo.pipeline import ROE_TEMPLATE
from harness.adapters.defectdojo_adapter import DefectDojoExport
from harness.analysis import FindingStore, Observation
from harness.approvals import ApprovalStore
from harness.assets import AssetGraph
from harness.audit import SqliteAuditLog
from harness.contracts import Guard, Harness, KillSwitch, Result
from harness.delivery import DeliveryContext, deliver, latest_report, record_delivery_decision
from harness.engagement import Engagement, State
from harness.evidence import build_evidence, write_evidence
from harness.policy_loader import phase_allowlist
from harness.report_catalog import ReportCatalog
from harness.reporting import ReportContext, generate_report
from harness.roe import parse_roe, roe_digest
from harness.schemas import CandidateFinding, PrioritizedVuln
from harness.tokens import TokenIssuer

ENG = "eng-1"
DD_HOST, DD_IP, DD_PORT = "defectdojo.tools.test", "10.97.0.20", 8080
DESTINATION = {"host": DD_HOST, "ip": f"{DD_IP}/32", "port": DD_PORT, "dd_engagement_id": 3}
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
    def __init__(self, tmp_path, entries=None, state=State.REPORT, eng=ENG,
                 destinations=None):
        self.eng = eng
        self.state_dir, self.audit_dir = tmp_path / "state", tmp_path / "audit"
        self.audit = SqliteAuditLog.open(eng, self.audit_dir)
        self.audit.record_control(eng, "scope-guard", "token.issue", "report", Result.OK)
        self.store = FindingStore.open(eng, self.state_dir)
        self.approvals = ApprovalStore.open(eng, self.state_dir)
        self.graph = AssetGraph.open(eng, self.state_dir)
        self.graph.add("domain", "dvwa.lab.test", source_tool="subfinder", iteration=1)
        self.graph.add("http_service", "http://dvwa.lab.test/", source_tool="httpx",
                       iteration=1)
        self.entries = copy.deepcopy(ENTRIES if entries is None else entries)
        self.engagement = in_state(state)
        # Fecha fija para que dos generaciones sean iguales byte a byte. Con destinos hace
        # falta emitir un token de REPORT de verdad, así que la ventana tiene que incluir ahora.
        when = (datetime(2026, 11, 20, 12, tzinfo=UTC) if destinations is None
                else datetime.now(UTC).replace(minute=0, second=0, microsecond=0))
        data = prepare_roe(eng, when, ROE_TEMPLATE)
        if destinations is not None:          # 007: destino del informe y fase REPORT
            data["report_destinations"] = destinations
            data["phases"] = [*data["phases"], "report"]
            data["approval"]["roe_sha256"] = roe_digest(data)
        self.roe = parse_roe(data)
        self.now = time.time()
        self.issuer = TokenIssuer(self.audit, key=b"k" * 32)
        self.connector = None
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
    def send(self, fid, result=Result.OK, host="dvwa.lab.test"):
        """El registro write-ahead que deja `Harness.invoke` antes de cada envío del loop C."""
        self.audit._append(engagement=self.eng, agent="validation-orchestrator",
                           action="poc_catalog.run_parametrized", target=host, phase="validate",
                           result=result, reason=None, evidence=None, subject=fid)

    def attempt(self, fid, n=1, result="validated", truncated=False, ok=True, sent=True,
                doc_fid=None, agent="validation-orchestrator"):
        if sent:
            self.send(fid)
        doc = build_evidence(finding_id=doc_fid or fid, attempt=n, poc_id="POC-CSP-001", poc_version="1.0.0",
                             catalog_version="0.2.0", parameters={"base_url": "http://x"},
                             sandbox_id=f"ptaas-sbx-{'ab' * 16}", request=None, record=None,
                             evaluator="header_missing_csp", canary=None, result=result,
                             detail="d", truncated=truncated)
        ref = write_evidence(self.state_dir, self.eng, doc_fid or fid, n, doc)
        self.audit.record_control(self.eng, agent, "validation.attempt", fid,
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
                             graph=self.graph, approvals=self.approvals,
                             previous=self.previous)

    def generate(self):
        return generate_report(self.ctx(), self.vulns, self.candidates)

    # -- entrega ---------------------------------------------------------------------------------
    def latest(self):
        return latest_report(self.audit.entries, self.eng, self.state_dir)

    def decide_delivery(self, report_id=None, decision="approved", sha=None, ack=False,
                        reviewer="beto", reason="revisado", at=None):
        latest = self.latest()
        return record_delivery_decision(
            self.approvals, self.audit, self.eng, self.state_dir, report_id or latest.report_id,
            decision, reviewer, reason, self.now if at is None else at,
            latest.short if sha is None else sha, ack)

    def harness(self, connector=None, resolver=None):
        def refuse(ip, port, timeout):            # por defecto, nadie sale a la red
            raise AssertionError(f"conexión inesperada a {ip}:{port}")
        adapter = DefectDojoExport(state_dir=self.state_dir,
                                   connector=connector or self.connector or refuse,
                                   limits=(2.0, 4096))
        return Harness(Guard(phase_allowlist()), self.audit, {"defectdojo.export": adapter},
                       KillSwitch(), self.issuer,
                       resolver=resolver or (lambda host: [DD_IP]))

    def delivery_ctx(self, harness=None):
        return DeliveryContext(self.engagement, self.roe, harness or self.harness(),
                               self.issuer, self.state_dir, self.approvals,
                               clock=lambda: self.now)

    def deliver(self, harness=None):
        return deliver(self.delivery_ctx(harness))

    def reports_dir(self):
        return self.state_dir / "reports" / self.eng

    def files(self):
        d = self.reports_dir()
        return sorted(p.name for p in d.iterdir()) if d.exists() else []
