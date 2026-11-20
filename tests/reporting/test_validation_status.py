"""Change 007 · reporting: validado y no validado visibles, desde la bitácora (D6, D7). Task 3.2."""
import json

import pytest

from harness.reporting import ReportError
from tests.reporting.helpers import Lab


def _finding(rep):
    (f,) = json.loads(rep.path.read_bytes())["findings"]
    return f


def test_validado_en_sandbox(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    ref = lab.attempt("f-1")
    rep = lab.generate()
    f = _finding(rep)
    assert f["validation"]["status"] == "validated" and f["evidence"] == [ref]
    assert "Validado en sandbox" in rep.markdown_path.read_text()


@pytest.mark.parametrize("reason,text", [
    ("reviewer_timeout", "no validado por falta de revisión"),
    ("no_catalog_entry", "sin verificación en el catálogo"),
    ("reviewer_rejected", "validación rechazada por el Reviewer"),
    ("request_budget_exhausted", "presupuesto de validación agotado"),
])
def test_no_validado_con_motivo(tmp_path, reason, text):
    lab = Lab(tmp_path)
    lab.finding("f-1", status="inconclusive")
    lab.closed("f-1", reason)
    rep = lab.generate()
    assert _finding(rep)["validation"] == {"status": "not_validated", "reason": reason,
                                           "text": text}
    assert f"No validado: {text}" in rep.markdown_path.read_text()


def test_confirmado_por_analisis_sin_validar(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", status="confirmed")
    rep = lab.generate()
    assert _finding(rep)["validation"]["text"] == "no se intentó validar"
    assert "confirmado por análisis, no validado en sandbox" in rep.markdown_path.read_text()


def test_evidencia_truncada_no_valida(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.attempt("f-1", truncated=True)
    assert _finding(lab.generate())["validation"]["text"] == "verificación negativa"


def test_intentos_negativos_y_errores(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.finding("f-2", cwe="CWE-1021")
    lab.attempt("f-1", result="not_validated")
    lab.attempt("f-2", result="failed", ok=False)
    doc = json.loads(lab.generate().path.read_bytes())
    texts = {f["finding_ids"][0]: f["validation"]["text"] for f in doc["findings"]}
    assert texts == {"f-1": "verificación negativa", "f-2": "error del sandbox"}


def test_bloqueado_y_pendiente(tmp_path):
    from harness.contracts import Action, Phase, ScopeToken
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.finding("f-2", cwe="CWE-1021")
    token = ScopeToken(lab.eng, ("10.99.0.0/24",), ("lab.test",), 0.0, 1e12, Phase.VALIDATE)
    action = Action("poc_catalog.run_parametrized", Phase.VALIDATE, requires_human_approval=True)
    lab.audit.record("validation-orchestrator", action, "dvwa.lab.test", token,
                     __import__("harness.contracts", fromlist=["Result"]).Result.BLOCKED,
                     "dns_out_of_scope", subject="f-1")
    lab.audit.record("validation-orchestrator", action, "dvwa.lab.test", token,
                     __import__("harness.contracts", fromlist=["Result"]).Result.PENDING_HITL,
                     subject="f-2")
    doc = json.loads(lab.generate().path.read_bytes())
    texts = {f["finding_ids"][0]: f["validation"]["text"] for f in doc["findings"]}
    assert texts == {"f-1": "bloqueado por alcance", "f-2": "pendiente de revisión"}


def test_cierre_validado_sin_respaldo(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.approvals.close("f-1", "validated", None, 1.0)
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "validation_mismatch"
    assert lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == "validation_mismatch"


def test_alto_no_validado_se_informa_igual(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-22", priority=9.0)
    lab.finding("f-2", cwe="CWE-693", priority=1.0)
    lab.closed("f-1", "no_catalog_entry")
    lab.attempt("f-2")
    rep = lab.generate()
    doc = json.loads(rep.path.read_bytes())
    first = doc["findings"][0]
    assert first["finding_ids"] == ["f-1"] and first["severity"] == "High"
    assert first["manual_check"] is True
    md = rep.markdown_path.read_text()
    assert "No validado: requiere verificación manual" in md
    sections = {s["key"]: s["content"] for s in doc["sections"]}
    assert [u["fingerprint"] for u in sections["risk_exposure"]["unvalidated_high"]] == [
        first["fingerprint"]]
    assert sections["executive_summary"]["unvalidated_high"] == 1


# --- el intento tiene que venir del loop C real (revisión de seguridad B1) -------------------
def _fails_with(lab, reason):
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == reason and lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == reason
    return exc.value


def test_intento_sin_envio_por_el_harness(tmp_path):
    """Un `validation.attempt` sin el OK write-ahead de `Harness.invoke` no valida nada."""
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.attempt("f-1", sent=False)
    assert "envío" in str(_fails_with(lab, "validation_mismatch"))


def test_mas_intentos_que_envios(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.attempt("f-1", n=1, result="not_validated")
    lab.attempt("f-1", n=2, sent=False)
    _fails_with(lab, "validation_mismatch")


def test_envio_de_otro_hallazgo_no_cuenta(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.finding("f-2", cwe="CWE-1021")
    lab.send("f-2")
    lab.attempt("f-1", sent=False)
    _fails_with(lab, "validation_mismatch")


def test_intento_registrado_por_otro_agente(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.attempt("f-1", agent="report-builder")
    _fails_with(lab, "validation_mismatch")


def test_evidencia_positiva_de_otro_hallazgo(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.finding("f-2", cwe="CWE-1021")
    lab.attempt("f-1", doc_fid="f-2")          # la evidencia de f-2 colgada de un intento de f-1
    _fails_with(lab, "evidence_mismatch")


def test_evidencia_de_otro_engagement(tmp_path):
    from harness.contracts import Result
    from harness.evidence import build_evidence, write_evidence
    lab = Lab(tmp_path)
    lab.finding("f-1")
    doc = build_evidence(finding_id="f-1", attempt=1, poc_id="POC-CSP-001", poc_version="1.0.0",
                         catalog_version="0.2.0", parameters={}, sandbox_id="s", request=None,
                         record=None, evaluator="e", canary=None, result="validated",
                         detail="d", truncated=False)
    ref = write_evidence(lab.state_dir, "eng-2", "f-1", 1, doc)
    lab.send("f-1")
    lab.audit.record_control(lab.eng, "validation-orchestrator", "validation.attempt", "f-1",
                             Result.OK, None, ref, "f-1")
    _fails_with(lab, "evidence_mismatch")


def test_archivo_de_evidencia_borrado(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    ref = lab.attempt("f-1")
    (lab.state_dir / ref.split("#")[0]).unlink()
    _fails_with(lab, "evidence_mismatch")


def test_evidencia_alterada_de_un_intento_abortado(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    ref = lab.attempt("f-1", result="failed", ok=False)
    path = lab.state_dir / ref.split("#")[0]
    path.write_text(path.read_text().replace("failed", "validated"))
    _fails_with(lab, "evidence_mismatch")


def test_rechazo_despues_del_pedido(tmp_path):
    """El pedido quedó PENDING_HITL y después el Reviewer lo rechazó, sin cierre todavía."""
    from harness.contracts import Result
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.send("f-1", Result.PENDING_HITL)
    lab.audit.record_control(lab.eng, "reviewer:beto", "hitl.reject", "dvwa.lab.test",
                             Result.OK, evidence="approvals/eng-1/1#sha256=" + "0" * 64,
                             subject="f-1")
    assert _finding(lab.generate())["validation"]["text"] == "validación rechazada por el Reviewer"
