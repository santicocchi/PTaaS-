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
    lab.finding("f-2", cwe="CWE-22", priority=7.0, host="juiceshop.lab.test")
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
    assert summary["posture"] == "crítica"
    assert summary["counts"]["Critical"] == {"validated": 0, "not_validated": 1}


def test_postura_alta(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-22")
    lab.finding("f-2", cwe="CWE-693")
    doc = json.loads(lab.generate().path.read_bytes())
    assert doc["sections"][0]["content"]["posture"] == "alta"
    assert "postura general de seguridad es alta" in doc["sections"][0]["content"]["text"]


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
