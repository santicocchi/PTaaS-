"""Ayudas del loop B: adaptadores con salidas grabadas (formato real de nuclei y ZAP)."""
from __future__ import annotations

import re
from pathlib import Path

from harness.analysis import AnalysisLoop, FalsePositive, FindingStore, load_equivalences
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase
from harness.policy_loader import phase_allowlist
from harness.schemas import CandidateFinding
from tests.conftest import TEST_ISSUER, make_token

DNS = {"dvwa.lab.test": ["10.99.0.2"]}


def nuclei_out(*findings, templates=("ptaas-missing-csp", "ptaas-server-version",
                                     "ptaas-missing-anticlickjacking",
                                     "ptaas-cookie-without-httponly")):
    return {"tool": "nuclei", "status": "ok", "invalid_lines": 0,
            "templates_run": list(templates), "skipped": [],
            "findings": [{"template_id": t, "cwe": cwe, "address": "10.99.0.2", "port": 80,
                          "url": url, "severity": "info", "evidence": []}
                         for t, cwe, url in findings]}


def zap_out(*alerts):
    return {"tool": "zap", "status": "ok", "invalid_lines": 0,
            "alerts": [{"plugin_id": p, "alert": p, "risk": risk, "confidence": conf,
                        "cwe": cwe, "url": url, "address": "10.99.0.2", "port": 80,
                        "evidence": "", "param": ""} for p, cwe, url, risk, conf in alerts]}


CSP_N = ("ptaas-missing-csp", "CWE-693", "http://dvwa.lab.test:80/")
CSP_Z = ("10038", "CWE-693", "http://dvwa.lab.test:80/", "Medium", "High")
SRV_Z_ROOT = ("10036", "CWE-497", "http://dvwa.lab.test:80/", "Low", "High")


class Scripted:
    def __init__(self, name, outputs, log):
        self.name, self.outputs, self.log = name, list(outputs), log
        self.allowed_phases, self.destructive = (Phase.ANALYZE,), False

    def run(self, action, target, token, addresses):
        self.log.append((self.name, target))
        out = self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]
        if isinstance(out, BaseException):
            raise out
        return out


class Lab:
    def __init__(self, tmp_path: Path, nuclei=(nuclei_out(),), zap=(zap_out(),), fps=(),
                 max_iterations=4, criticality=lambda h: (3, True), store=None):
        self.log: list[tuple[str, str]] = []
        self.adapters = {"nuclei.safe_templates": Scripted("nuclei.safe_templates", nuclei,
                                                           self.log),
                         "zap.baseline_scan": Scripted("zap.baseline_scan", zap, self.log)}
        self.audit = AuditLog()
        self.harness = Harness(Guard(phase_allowlist()), self.audit, self.adapters, KillSwitch(),
                               TEST_ISSUER, resolver=lambda h: DNS.get(h, []))
        self.token = make_token(Phase.ANALYZE, cidrs=("10.99.0.0/24",),
                                domains=("dvwa.lab.test",))
        self.store = store or FindingStore.open("eng-1", tmp_path)
        self.loop = AnalysisLoop(self.harness, self.token, self.store,
                                 asset_of=lambda h: f"asset-{h}", criticality_of=criticality,
                                 equivalences=load_equivalences(),
                                 false_positives=list(fps), max_iterations=max_iterations)

    def run(self, candidates=(), hosts=("dvwa.lab.test",)):
        return self.loop.run(list(candidates), list(hosts))


def fp(check, pattern, tool="zap", approved=True, fid="FP-T1"):
    return FalsePositive(fid, tool, check, re.compile(pattern), "conocido del lab", approved)


def version_candidate(cve="CVE-2099-0001", cwe="CWE-22", cvss=8.7, version="4.0", epss=0.42):
    return CandidateFinding(id=f"f-{cve}", asset_id="asset-dvwa.lab.test", cwe=cwe, cve=cve,
                            epss=epss, evidence_refs=[f"feed:nvd:{cve}", "tool:nmap"],
                            confidence="low", cvss_score=cvss, cvss_version=version,
                            host="dvwa.lab.test", title=cve)


def by_cwe(result):
    cands = {c.id: c for c in result.candidates}
    return {cands[v.finding_id].cwe: v for v in result.vulns}
