"""Change 006 · validation: evidencia redactada con hash referenciado en bitácora (D7)."""
import hashlib
import json

import pytest

from harness.contracts import EVIDENCE_RE, AuditLog, Result
from harness.evidence import build_evidence, verify_evidence, write_evidence
from harness.poc.catalog import ResponseRecord
from harness.sandbox import SandboxRequest

REQ = SandboxRequest("GET", "/login.php", "dvwa.lab.test", "10.99.0.10", 80)


def doc(record, *, canary=None, evaluator="header_missing_csp", result="validated"):
    return build_evidence(
        finding_id="F-1", attempt=1, poc_id="POC-CSP-001", poc_version="1.0.0",
        catalog_version="0.2.0", parameters={"base_url": "http://dvwa.lab.test", "path": "/"},
        sandbox_id="ptaas-sbx-1", request=REQ, record=record, evaluator=evaluator,
        canary=canary, result=result, detail="sin Content-Security-Policy", truncated=False)


def test_que_se_guarda():
    d = doc(ResponseRecord(200, {"Server": "Apache"}, "<html>"))
    for key in ("poc_id", "poc_version", "catalog_version", "parameters", "sandbox_id",
                "attempt", "finding_id"):
        assert key in d
    assert d["request"] == {"method": "GET", "path": "/login.php", "host": "dvwa.lab.test",
                            "ip": "10.99.0.10", "port": 80}
    assert d["result"] == "validated" and d["truncated"] is False


def test_cookie_en_la_respuesta():
    r = ResponseRecord(200, {"Set-Cookie": "PHPSESSID=abc123; HttpOnly"}, "",
                       ("PHPSESSID=abc123; HttpOnly",))
    text = json.dumps(doc(r, evaluator="cookie_flags_missing"))
    assert "abc123" not in text
    d = json.loads(text)
    assert d["response"]["set_cookies"] == [{"name": "PHPSESSID", "attributes": ["HttpOnly"]}]
    assert d["response"]["headers"]["Set-Cookie"] == "[redacted]"


@pytest.mark.parametrize("name", ["Authorization", "cookie", "SET-COOKIE"])
def test_encabezados_sensibles_redactados(name):
    d = doc(ResponseRecord(200, {name: "Bearer secreto"}, ""))
    assert "secreto" not in json.dumps(d)
    assert d["response"]["headers"][name] == "[redacted]"


def test_solo_encabezados_permitidos():
    d = doc(ResponseRecord(200, {"Server": "Apache", "X-Debug-Token": "t0k",
                                 "content-type": "text/html"}, ""))
    assert d["response"]["headers"] == {"Server": "Apache", "content-type": "text/html"}


def test_cuerpo_grande():
    body = "<html>" + "x" * 30_000 + "ptaasdeadbeef\"'<>" + "y" * 31_000
    r = ResponseRecord(200, {}, body)
    d = doc(r, canary="ptaasdeadbeef\"'<>", evaluator="input_reflected_unencoded")
    assert d["response"]["body_sha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert len(d["response"]["excerpt"].encode()) <= 512
    assert "ptaasdeadbeef" in d["response"]["excerpt"]
    assert len(json.dumps(d)) < 4096                  # el resto del cuerpo no se guarda


def test_extracto_alrededor_de_la_coincidencia_del_evaluador():
    body = "z" * 5000 + "Fatal error: Uncaught Exception in x.php on line 12" + "z" * 5000
    d = doc(ResponseRecord(500, {}, body), evaluator="verbose_error_disclosure")
    assert "Fatal error" in d["response"]["excerpt"]
    assert len(d["response"]["excerpt"].encode()) <= 512


def test_sin_coincidencia_no_hay_extracto():
    d = doc(ResponseRecord(200, {}, "datos del laboratorio"), evaluator="header_missing_csp")
    assert d["response"]["excerpt"] == ""


def test_intento_fallido_sin_respuesta():
    d = build_evidence(
        finding_id="F-1", attempt=2, poc_id="POC-CSP-001", poc_version="1.0.0",
        catalog_version="0.2.0", parameters={}, sandbox_id="ptaas-sbx-2", request=REQ,
        record=None, evaluator="header_missing_csp", canary=None, result="failed",
        detail="sandbox_error: código 137", truncated=False)
    assert d["response"] is None and d["result"] == "failed"


def test_resultado_invalido_se_rechaza():
    with pytest.raises(ValueError):
        doc(ResponseRecord(200, {}, ""), result="maybe")


def test_referencia_en_bitacora(tmp_path):
    ref = write_evidence(tmp_path, "eng-1", "F-1", 1, doc(ResponseRecord(200, {}, "")))
    assert EVIDENCE_RE.match(ref) and ref.startswith("evidence/eng-1/F-1-1.json#sha256=")
    AuditLog().record_control("eng-1", "v", "validation.attempt", "F-1", Result.OK,
                              evidence=ref)
    assert verify_evidence(tmp_path, ref)


def test_evidencia_alterada(tmp_path):
    ref = write_evidence(tmp_path, "eng-1", "F-1", 1, doc(ResponseRecord(200, {}, "")))
    path = tmp_path / ref.split("#", 1)[0]
    path.write_text(path.read_text().replace("validated", "not_validated"))
    assert not verify_evidence(tmp_path, ref)


def test_evidencia_no_se_sobrescribe(tmp_path):
    write_evidence(tmp_path, "eng-1", "F-1", 1, doc(ResponseRecord(200, {}, "")))
    with pytest.raises(FileExistsError):
        write_evidence(tmp_path, "eng-1", "F-1", 1, doc(ResponseRecord(200, {}, "")))


@pytest.mark.parametrize("ref", ["../x.json#sha256=" + "a" * 64, "evidence/x.json",
                                 "evidence/nope.json#sha256=" + "a" * 64])
def test_referencia_invalida_o_inexistente(tmp_path, ref):
    assert not verify_evidence(tmp_path, ref)


@pytest.mark.parametrize("eng,finding", [("../x", "F-1"), ("eng-1", "../F"), ("eng-1", "")])
def test_nombres_invalidos(tmp_path, eng, finding):
    with pytest.raises(ValueError):
        write_evidence(tmp_path, eng, finding, 1, {})


# --- revisión M9: Location sin query ni fragmento ---------------------------------------------
@pytest.mark.parametrize("location,expected", [
    ("http://dvwa.lab.test/login.php?token=s3cret#frag", "http://dvwa.lab.test/login.php"),
    ("/index.php?PHPSESSID=s3cret", "/index.php"),
    ("login.php#s3cret", "login.php"),
    ("http://dvwa.lab.test/", "http://dvwa.lab.test/"),
])
def test_location_sin_query_ni_fragmento(location, expected):
    d = doc(ResponseRecord(302, {"Location": location}, ""))
    assert d["response"]["headers"]["Location"] == expected
    assert "s3cret" not in json.dumps(d)
