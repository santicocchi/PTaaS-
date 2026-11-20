"""Change 007 · reporting: informe armado desde los hallazgos y la bitácora (D2). Task 2.1, 2.2."""
import json
import sqlite3

import pytest

from harness.contracts import AuditIntegrityError
from harness.engagement import State
from harness.reporting import ReportError
from tests.reporting.helpers import Lab


def test_evidencia_del_loop_c_en_el_informe(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    ref = lab.attempt("f-1")
    rep = lab.generate()
    doc = json.loads(rep.path.read_bytes())
    sections = {s["key"]: s["content"] for s in doc["sections"]}
    assert doc["findings"][0]["evidence"] == [ref]
    assert sections["annex_evidence"]["refs"] == [ref]
    (gen,) = lab.control("report.generated")
    assert gen["subject"] == "report-v1" and gen["evidence"] == rep.ref
    assert rep.ref.startswith("reports/eng-1/report-v1.json#sha256=")


def test_evidencia_alterada(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    ref = lab.attempt("f-1")
    path = lab.state_dir / ref.split("#")[0]
    path.write_text(path.read_text().replace('"validated"', '"validatedX"'))
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "evidence_mismatch" and ref in str(exc.value)
    assert lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == "evidence_mismatch"


def test_cadena_rota(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.closed("f-1", "no_catalog_entry")
    lab.closed("f-1", "no_catalog_entry")
    with sqlite3.connect(lab.audit_dir / "eng-1.sqlite3") as con:   # registro intermedio
        con.execute("DROP TRIGGER IF EXISTS audit_no_update")
        con.execute("UPDATE audit SET target = 'otro' WHERE seq = 2")
    with pytest.raises(AuditIntegrityError):
        lab.generate()
    assert lab.files() == []


@pytest.mark.parametrize("state,reason", [(State.VALIDATE, "engagement_not_in_report"),
                                          (State.DELIVERED, "engagement_delivered")])
def test_engagement_fuera_de_report(tmp_path, state, reason):
    lab = Lab(tmp_path, state=State.REPORT)
    if state == State.DELIVERED:
        from harness.engagement import _DELIVERY_GRANT
        lab.engagement.grant_delivery(_DELIVERY_GRANT)
        lab.engagement.advance()
    else:
        lab.engagement.state = state
    lab.finding("f-1")
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == reason and lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == reason


def test_host_fuera_del_laboratorio(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", host="app.example.com")
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "not_lab_target" and lab.files() == []


def test_epss_junto_al_cvss(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", epss=0.973)
    lab.finding("f-2", cwe="CWE-1021")
    lab.finding("f-3", cwe="CWE-22", epss=0.5, feed_stale=True)
    doc = json.loads(lab.generate().path.read_bytes())
    epss = {f["finding_ids"][0]: f["epss"]["text"] for f in doc["findings"]}
    assert epss["f-1"].startswith("0.973 (snapshot del ") and epss["f-2"] == "sin dato"
    assert epss["f-3"] == "0.500 (dato desactualizado)"
    f1 = next(f for f in doc["findings"] if f["finding_ids"] == ["f-1"])
    assert (f1["cvss_v4_score"], f1["severity"]) == ("2.1", "Low")


def test_host_excluido_por_el_roe(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", host="juiceshop.lab.test")       # en la lista `exclusions` del RoE
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "out_of_scope" and lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == "out_of_scope"


@pytest.mark.parametrize("side", ["vuln", "candidate", "repeated"])
def test_hallazgo_sin_par_no_desaparece(tmp_path, side):
    from harness.schemas import CandidateFinding, PrioritizedVuln
    lab = Lab(tmp_path)
    lab.finding("f-1")
    if side == "vuln":
        lab.vulns.append(PrioritizedVuln(finding_id="f-9", status="confirmed", rationale="r"))
    elif side == "candidate":
        lab.candidates.append(CandidateFinding(id="f-9", asset_id="a", cwe="CWE-22",
                                               evidence_refs=["zap:1@http://dvwa.lab.test/"],
                                               host="dvwa.lab.test"))
    else:
        lab.vulns.append(lab.vulns[0])
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "finding_mismatch" and lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == "finding_mismatch"


def test_bitacora_con_entrega_aunque_el_estado_diga_report(tmp_path):
    """El Engagement no persiste: la bitácora manda."""
    from tests.reporting.helpers import in_state
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    lab.deliver()
    lab.engagement = in_state(State.REPORT)              # recién armado: no sabe nada
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "engagement_delivered"
    assert "report-v2.json" not in lab.files()


def test_error_inesperado_queda_en_la_bitacora(tmp_path, monkeypatch):
    from harness import reporting

    def boom(*a, **k):
        raise RuntimeError("falla interna")
    monkeypatch.setattr(reporting, "build", boom)
    lab = Lab(tmp_path)
    lab.finding("f-1")
    with pytest.raises(RuntimeError):
        lab.generate()
    assert lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == "internal_error"


def test_falla_al_registrar_no_deja_archivos_huerfanos(tmp_path, monkeypatch):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    original = lab.audit.record_control

    def record(eng, agent, action, *a, **k):
        if action == "report.generated":
            raise OSError("disco lleno")
        return original(eng, agent, action, *a, **k)
    monkeypatch.setattr(lab.audit, "record_control", record)
    with pytest.raises(OSError):
        lab.generate()
    assert lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == "internal_error"
    monkeypatch.undo()
    assert lab.generate().report_id == "report-v1"


def test_feed_distinto_y_epss_sin_fecha(tmp_path, monkeypatch):
    from harness import reporting
    monkeypatch.setattr(reporting, "_feeds", lambda: {"epss_date": None,
                                                      "manifest_sha256": None})
    lab = Lab(tmp_path)
    lab.finding("f-1", epss=0.2, cvss=(9.9, "4.0"))
    lab.finding("f-2", cwe="CWE-1021", cvss=(9.9, "3.1"))
    doc = json.loads(lab.generate().path.read_bytes())
    by = {f["finding_ids"][0]: f for f in doc["findings"]}
    assert by["f-1"]["epss"]["text"] == "0.200 (snapshot sin fecha)"
    assert by["f-1"]["feed_cvss"]["differs"] is True
    assert by["f-2"]["feed_cvss"]["differs"] is False      # un 3.1 no se compara con el 4.0
    assert by["f-1"]["cvss_v4_nomenclature"] == "CVSS-B"


def test_orden_por_la_prioridad_sin_redondear(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", priority=7.001)
    lab.finding("f-2", cwe="CWE-1021", priority=7.004)
    doc = json.loads(lab.generate().path.read_bytes())
    assert [f["finding_ids"][0] for f in doc["findings"]] == ["f-2", "f-1"]


def test_descartado_con_intento_positivo_se_senala(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.finding("f-2", cwe="CWE-1021", status="discarded", rationale="FP-001")
    lab.attempt("f-2")
    rep = lab.generate()
    annex = {s["key"]: s["content"] for s in json.loads(rep.path.read_bytes())["sections"]}
    (d,) = annex["annex_discarded"]["findings"]
    assert d["validated_in_sandbox"] is True
    assert "revisar el descarte" in rep.markdown_path.read_text()
