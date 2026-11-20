"""Change 007 · reporting: estructura PTES §7 y resumen ejecutivo (D5, D8). Task 2.4."""
import json
import re

import pytest

from harness.reporting import SECTIONS
from tests.reporting.helpers import Lab


@pytest.fixture
def report(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-22", cve="CVE-2021-41773", priority=9.0)
    lab.finding("f-2", cwe="CWE-22", priority=7.0, asset="asset-dvwa-2")
    lab.finding("f-3", cwe="CWE-693", priority=1.0)
    lab.observe("dvwa.lab.test", "CWE-693", "http://10.99.0.4/", "sin CSP")
    lab.attempt("f-3")
    rep = lab.generate()
    return json.loads(rep.path.read_bytes()), rep.markdown_path.read_text()


def test_orden_de_las_secciones(report):
    doc, md = report
    titles = [ln[2:] for ln in md.splitlines() if ln.startswith("# ")]
    assert titles == [f"{sid}. {title}" for sid, _, title in SECTIONS]
    assert [s["key"] for s in doc["sections"]] == [key for _, key, _ in SECTIONS]


def test_resumen_sin_jerga(report):
    doc, md = report
    summary = doc["sections"][0]["content"]
    text = json.dumps(summary, ensure_ascii=False)
    for bad in ("CVE-", "CWE-", "CVSS:", "#sha256=", "10.99."):
        assert bad not in text
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
    md_summary = md.split("# 2.")[0]
    assert "CVE-" not in md_summary and "CVSS:" not in md_summary
    assert summary["posture"] == "crítico"
    assert summary["counts"]["Critical"] == {"validated": 0, "not_validated": 1}


def test_riesgo_alto(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-22")
    lab.finding("f-2", cwe="CWE-693")
    doc = json.loads(lab.generate().path.read_bytes())
    assert doc["sections"][0]["content"]["posture"] == "alto"
    assert "nivel de riesgo general es alto" in doc["sections"][0]["content"]["text"]


def test_resumen_sin_repetir_el_mismo_hallazgo(tmp_path):
    """El mismo hallazgo en dos hosts aparece una vez en el resumen (recorrido del lab)."""
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-22", priority=9.0)
    lab.finding("f-2", cwe="CWE-22", host="www.dvwa.lab.test", priority=8.0)
    lab.finding("f-3", cwe="CWE-693", priority=1.0)
    summary = json.loads(lab.generate().path.read_bytes())["sections"][0]["content"]
    csp = "Falta la política de seguridad de contenido"
    assert [t["title"] for t in summary["top"]] == ["Lectura de archivos fuera del sitio", csp]
    assert len(summary["recommendations"]) == len(set(summary["recommendations"]))
    assert "0 se confirmaron" in summary["text"]


def test_un_solo_confirmado_en_singular(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", priority=5.0)
    lab.attempt("f-1")
    lab.approvals.close("f-1", "validated", None, 1.0)
    text = json.loads(lab.generate().path.read_bytes())["sections"][0]["content"]["text"]
    assert "1 se confirmó en un entorno aislado" in text


def test_alcance_sin_datos_de_contacto(report):
    doc, md = report
    scope = doc["sections"][1]["content"]["scope"]
    assert re.fullmatch(r"[0-9a-f]{64}", scope["roe_sha256"])
    assert scope["window_start"].endswith("Z") and scope["window_end"].endswith("Z")
    raw = json.dumps(doc, ensure_ascii=False) + md
    for bad in ("reviewer@lab", "Responsable del laboratorio", "lab-ptaas", "emergency"):
        assert bad not in raw


def test_post_explotacion_y_sin_hora_de_generacion(report):
    doc, _ = report
    sections = {s["key"]: s["content"] for s in doc["sections"]}
    assert "no se realiza explotación" in sections["post_exploitation"]["text"]
    assert doc["as_of"] == sections["annex_audit"]["as_of"]
    assert "generated_at" not in json.dumps(doc)


@pytest.mark.parametrize("text", ["ver fe80::1", "2001:db8:0:0:0:0:0:1", "en https://x.lab",
                                  "el archivo data/feeds", "policy.yaml", "10.99.0.5",
                                  "CWE-79", "CVSS:4.0/AV:N", "#sha256=ab"])
def test_jerga_que_se_detecta(text):
    from harness.report_catalog import has_jargon
    assert has_jargon(text)


@pytest.mark.parametrize("text", ["Configurar una política restrictiva.",
                                  "La reunión es a las 10:30", "Cookie de sesión sin Secure"])
def test_texto_para_no_tecnicos(text):
    from harness.report_catalog import has_jargon
    assert not has_jargon(text)


def test_jerga_en_el_resumen_tiene_su_motivo(tmp_path, monkeypatch):
    from harness import reporting
    from harness.reporting import ReportError
    from tests.reporting.helpers import Lab
    monkeypatch.setattr(reporting, "first_sentence", lambda t: "Ver la ruta /etc/x/ del host.")
    lab = Lab(tmp_path)
    lab.finding("f-1")
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "summary_jargon" and lab.files() == []


def test_activo_fuera_del_alcance_no_se_publica(tmp_path):
    """El grafo lo escribe quien relevó: un activo marcado en alcance que no está en el
    laboratorio o en el RoE (o está excluido) no aparece en la sección 3."""
    lab = Lab(tmp_path)
    lab.finding("f-1")
    for host in ("juiceshop.lab.test", "app.example.com"):
        lab.graph.add("domain", host, source_tool="x", iteration=1)
    lab.graph.add("http_service", "http://203.0.113.7/", source_tool="x", iteration=1)
    doc = json.loads(lab.generate().path.read_bytes())
    (gathering,) = [s["content"] for s in doc["sections"] if "assets" in s["content"]]
    assert [a["host"] for a in gathering["assets"]] == ["dvwa.lab.test"]
    assert "app.example.com" not in json.dumps(doc) and "203.0.113.7" not in json.dumps(doc)
