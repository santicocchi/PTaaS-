"""Change 007 · authorization: el gate de entrega lo decide la política (D15)."""
import pytest

from harness.contracts import Action, Phase, ScopeViolation
from tests.reporting.helpers import DD_HOST, DESTINATION, Lab


class Spy:
    """Adaptador falso de `defectdojo.export`: anota si se ejecutó."""
    name = "defectdojo.export"
    allowed_phases = (Phase.REPORT,)
    destructive = False

    def __init__(self):
        self.calls = []

    def run(self, action, target, token, addresses):
        raise AssertionError("siempre con subject")

    def run_subject(self, action, target, token, addresses, subject):
        self.calls.append(subject)
        return {"status": "ok"}


@pytest.fixture
def setup(tmp_path):
    lab = Lab(tmp_path, destinations=[DESTINATION])
    h = lab.harness()
    spy = Spy()
    h.tools["defectdojo.export"] = spy
    return lab, h, spy, lab.issuer.issue(lab.roe, Phase.REPORT)


def _approve(h, subject):
    h.guard.approve("defectdojo.export", DD_HOST, engagement_id="eng-1", phase=Phase.REPORT,
                    subject=subject)


def test_exportacion_declarada_sin_aprobacion(setup):
    lab, h, spy, token = setup
    action = Action("defectdojo.export", Phase.REPORT, requires_human_approval=False)
    out = h.invoke("report-delivery", action, DD_HOST, token, subject="report-v1")
    assert out == {"status": "PENDING_HITL"} and spy.calls == []
    assert lab.audit.entries[-1]["result"] == "PENDING_HITL"


def test_exportacion_sin_sujeto(setup):
    _lab, h, spy, token = setup
    _approve(h, "report-v1")
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("report-delivery", Action("defectdojo.export", Phase.REPORT), DD_HOST, token)
    assert exc.value.reason == "missing_subject" and spy.calls == []


def test_aprobacion_de_otra_version(setup):
    _lab, h, spy, token = setup
    _approve(h, "report-v1")
    out = h.invoke("report-delivery", Action("defectdojo.export", Phase.REPORT), DD_HOST,
                   token, subject="report-v2")
    assert out == {"status": "PENDING_HITL"} and spy.calls == []


def test_exportacion_aprobada(setup):
    lab, h, spy, token = setup
    _approve(h, "report-v1")
    h.invoke("report-delivery", Action("defectdojo.export", Phase.REPORT), DD_HOST, token,
             subject="report-v1")
    assert spy.calls == ["report-v1"]
    ok = [e for e in lab.audit.entries if e["action"] == "defectdojo.export"]
    assert [(e["result"], e["subject"]) for e in ok] == [("OK", "report-v1")]


def test_la_politica_declara_el_gate():
    from harness.policy_loader import hitl_capabilities
    assert "defectdojo.export" in hitl_capabilities()
