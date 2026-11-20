"""Change 007 · reporting: sin datos sensibles en el informe (D13)."""
import pytest

from harness.redaction import PATTERNS, SensitiveData, redact, scan

SHA = "ab" * 32

# Un texto que el patrón tiene que detectar, el valor que no puede quedar y uno parecido que no.
CASES = {
    "auth-header": ("Authorization: Basic YWRtaW46cGFzc3dvcmQ=", "YWRtaW46cGFzc3dvcmQ=",
                    "authorization requerida"),
    "bearer": ("Bearer eyJhbGciOiJIUzI1NiJ9xyz", "eyJhbGciOiJIUzI1NiJ9xyz", "bearer"),
    "cookie-value": ("Set-Cookie: security=low; path=/", "security=low", "Set-Cookie sin valor"),
    "session-id": ("PHPSESSID=abc123def", "abc123def", "PHPSESSID"),
    "jwt": ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJh",
            "eyJzdWIiOiIxIn0.c2lnbmF0dXJh", "eyJ corto"),
    "credential-param": ("password=s3cret", "s3cret", "password"),
    "url-query": ("http://dvwa.lab.test/x?token=s3cret", "token=s3cret",
                  "http://dvwa.lab.test/login.php"),
    "private-key": ("-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY",
                    "-----BEGIN CERTIFICATE-----"),
    "aws-key": ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP", "AKIA corta"),
    "email": ("admin@juice-sh.op", "admin@juice-sh.op", "reviewer@lab"),
    "md5-hash": ("5f4dcc3b5aa765d61d8327deb882cf99", "5f4dcc3b5aa765d61d8327deb882cf99", SHA),
    "canary": ("ptaas1a2b3c4d", "ptaas1a2b3c4d", "ptaas-sandbox"),
    "lab-default-cred": ("admin:password", "admin:password", "admin: el usuario"),
}


def test_hay_un_caso_por_patron():
    assert set(CASES) == {p.id for p in PATTERNS}


@pytest.mark.parametrize("pid", sorted(CASES))
def test_patron_detecta_y_redacta(pid):
    text, secret, harmless = CASES[pid]
    out = redact(f"antes {text} después")
    assert secret not in out and "[redacted:" in out
    assert pid in {m.pattern for m in scan(text, "s")}
    assert pid not in {m.pattern for m in scan(harmless, "s")}


def test_lista_completa_no_deja_valores():
    texts = [c[0] for c in CASES.values()]
    out = redact("\n".join(texts))
    for _, secret, _ in CASES.values():
        assert secret not in out
    assert scan(out, "x") == []


def test_cookie_de_zap_redactada():
    out = redact("Set-Cookie: PHPSESSID=abc123; HttpOnly")
    assert "abc123" not in out and "[redacted:" in out


def test_hashes_de_la_bitacora_intactos():
    text = (f"evidence/eng-1/f-1-1.json#sha256={SHA} y el hash corto 70bcfe921dd5, "
            f"la huella fp1-{'0a' * 16}")
    assert scan(text, "anexo") == []
    assert redact(text) == text


def test_scan_no_muestra_el_valor():
    (m,) = scan("contacto: admin@juice-sh.op", "titulo")
    assert (m.pattern, m.section) == ("email", "titulo")
    with pytest.raises(SensitiveData) as exc:
        SensitiveData.check({"titulo": "contacto: admin@juice-sh.op"})
    assert "email" in str(exc.value) and "titulo" in str(exc.value)
    assert "juice-sh" not in str(exc.value)


def test_check_recorre_estructuras():
    doc = {"a": [{"b": "ok"}, {"c": "Bearer abcdefgh123"}], "n": 3}
    with pytest.raises(SensitiveData) as exc:
        SensitiveData.check(doc)
    assert exc.value.matches[0].section == "a[1].c"


# --- en el informe ---------------------------------------------------------------------------
def test_cookie_de_zap_no_llega_al_informe(tmp_path):
    from tests.reporting.helpers import Lab
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.observe("dvwa.lab.test", "CWE-693", "http://dvwa.lab.test/?id=7",
                "Set-Cookie: PHPSESSID=abc123; HttpOnly")
    rep = lab.generate()
    for raw in (rep.path.read_text(), rep.markdown_path.read_text()):
        assert "abc123" not in raw and "id=7" not in raw and "[redacted:" in raw


def test_dato_sensible_que_no_paso_por_la_redaccion(tmp_path):
    """El escaneo final es la red de seguridad: un campo que no se redacta igual se controla."""
    import json

    from harness.reporting import ReportError, build
    from tests.reporting.helpers import Lab
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    inputs = json.loads((lab.reports_dir() / "inputs-v1.json").read_bytes())
    inputs["inputs_ref"] = "reports/eng-1/inputs-v1.json#sha256=" + "0" * 64
    inputs["roe"]["exclusions"] = ["admin@juice-sh.op"]
    with pytest.raises(ReportError) as exc:
        build(inputs, lab.audit.entries, lab.state_dir)
    assert exc.value.reason == "sensitive_data"
    assert "email" in str(exc.value) and "juice-sh" not in str(exc.value)
