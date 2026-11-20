"""Change 007 · reporting: exportación a DefectDojo por lista permitida (D12, D16). Task 2.5."""
import json
import socket

import pytest

from harness.defectdojo import DD_FIELDS, ExportError, build_export
from harness.reporting import fingerprint
from tests.reporting.helpers import Lab


def _report(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", priority=5.0)                         # validado
    lab.finding("f-2", cwe="CWE-22", priority=9.0)           # High, no validado
    lab.finding("f-3", cwe="CWE-1021", status="discarded", rationale="FP-001")
    lab.observe("dvwa.lab.test", "CWE-693", "http://dvwa.lab.test/",
                "Content-Security-Policy ausente; extracto-interno-123")
    lab.attempt("f-1")
    lab.closed("f-2", "no_catalog_entry")
    lab.approvals.close("f-1", "validated", None, 1.0)
    rep = lab.generate()
    return lab, rep, json.loads(rep.path.read_bytes())


def test_campos_exportados(tmp_path):
    _lab, rep, doc = _report(tmp_path)
    out = build_export(doc, rep.ref.split("=", 1)[1])
    by = {f["unique_id_from_tool"]: f for f in out["findings"]}
    assert all(tuple(f) == DD_FIELDS for f in out["findings"])
    ok = by[fingerprint("asset-dvwa.lab.test", "CWE-693")]
    high = by[fingerprint("asset-dvwa.lab.test", "CWE-22")]
    assert ok["verified"] is True and "validated" in ok["tags"]
    assert high["verified"] is False and "not-validated" in high["tags"]
    assert high["severity"] == "High" and high["cwe"] == 22
    assert ok["active"] is True and ok["false_p"] is False


def test_nada_interno_en_la_exportacion(tmp_path):
    _lab, rep, doc = _report(tmp_path)
    raw = json.dumps(build_export(doc, rep.ref.split("=", 1)[1]), ensure_ascii=False)
    for forbidden in ("extracto-interno-123", "ptaas-sbx-", "base_url", "http://x", "state/",
                      "evidence/", "10.97.0.", "beto", "reviewer", "rationale", "FP-001",
                      "Responsable del laboratorio", "juiceshop", "#sha256="):
        assert forbidden not in raw, forbidden
    # Solo viaja el SHA-256 de la evidencia, sin ruta.
    (ref,) = next(f for f in doc["findings"] if f["evidence"])["evidence"]
    assert ref.split("#sha256=", 1)[1] in raw


def test_descartado_y_divulgacion_fuera(tmp_path):
    _lab, rep, doc = _report(tmp_path)
    raw = json.dumps(build_export(doc, rep.ref.split("=", 1)[1]))
    assert fingerprint("asset-dvwa.lab.test", "CWE-1021") not in raw
    assert "not_applicable_lab" not in raw


def test_dato_sensible_en_la_exportacion(tmp_path):
    _lab, rep, doc = _report(tmp_path)
    doc["findings"][0]["title"] = "Contacto admin@juice-sh.op"
    with pytest.raises(ExportError) as exc:
        build_export(doc, rep.ref.split("=", 1)[1])
    assert exc.value.reason == "sensitive_data" and "juice-sh" not in str(exc.value)


def test_dato_sensible_no_se_entrega_ni_se_escribe(tmp_path, monkeypatch):
    from harness import delivery
    from harness.delivery import DeliveryError
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()

    def leaky(doc, sha):
        raise ExportError("sensitive_data", "email en defectdojo.findings[0].title")
    monkeypatch.setattr(delivery, "build_export", leaky)
    with pytest.raises(DeliveryError) as exc:
        lab.deliver()
    assert exc.value.reason == "sensitive_data"
    assert not any(n.startswith(("defectdojo-", "delivered-")) for n in lab.files())
    (aborted,) = lab.control("report.delivery")
    assert (aborted["result"], aborted["reason"]) == ("ABORTED", "sensitive_data")


def test_modo_sin_instancia_sin_abrir_conexiones(tmp_path, monkeypatch):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()

    def no_network(*a, **k):
        raise AssertionError("el modo offline no abre conexiones")
    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    result = lab.deliver()
    assert result.mode == "offline"
    exported = json.loads((lab.reports_dir() / "defectdojo-report-v1.json").read_bytes())
    assert set(exported) == {"findings"} and set(exported["findings"][0]) == set(DD_FIELDS)
    receipt = json.loads((lab.state_dir / result.receipt.split("#")[0]).read_bytes())
    assert receipt["mode"] == "offline" and receipt["export"] == result.export
    assert result.export.startswith("reports/eng-1/defectdojo-report-v1.json#sha256=")
    (done,) = lab.control("report.delivered")
    assert done["target"] == "offline" and done["evidence"] == result.receipt


@pytest.mark.parametrize("leak", ["ver evidence/eng-1/f-1-1.json", "sandbox ptaas-sbx-ab12",
                                  "runner en 10.97.0.10", "decidió reviewer:beto"])
def test_referencia_interna_no_sale(tmp_path, leak):
    """Red de seguridad además de la lista permitida: una marca interna aborta."""
    _lab, rep, doc = _report(tmp_path)
    doc["findings"][0]["technical_description"] += f" ({leak})"
    with pytest.raises(ExportError) as exc:
        build_export(doc, rep.ref.split("=", 1)[1])
    assert exc.value.reason == "sensitive_data"
