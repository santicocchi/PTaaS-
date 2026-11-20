"""Change 007 · reporting: plantilla ISO/IEC 29147 para hallazgos del laboratorio (D11)."""
import json

import pytest

from harness.reporting import ReportError
from tests.reporting.helpers import Lab


def test_aviso_de_un_hallazgo_de_dvwa(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.attempt("f-1")
    doc = json.loads(lab.generate().path.read_bytes())
    (adv,) = doc["sections"][11]["content"]["advisories"]
    first = next(e for e in lab.audit.entries if e["action"] == "validation.attempt")
    assert adv["disclosure_status"] == "not_applicable_lab"
    assert adv["id"] == doc["findings"][0]["fingerprint"]
    from harness.reporting import _ts
    assert adv["timeline"]["first_validation"] == _ts(first["ts"])
    assert adv["contact"] == "equipo de divulgación del servicio"
    assert "@" not in json.dumps(adv)


def test_host_fuera_del_laboratorio(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", host="app.example.com")
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "not_lab_target"
    assert lab.files() == []
