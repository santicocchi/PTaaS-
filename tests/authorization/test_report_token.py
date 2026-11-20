"""Change 007 · authorization: destinos del informe en el RoE y token de REPORT (D15)."""
import pytest

from harness.contracts import Action, Phase, ScopeViolation
from harness.roe import RoEError, parse_roe, roe_digest
from tests.reporting.helpers import DD_HOST, DD_IP, DESTINATION, Lab

EXPORT = Action("defectdojo.export", Phase.REPORT)


def _roe_data(lab, destinations):
    data = dict(lab.roe.source)
    data["report_destinations"] = destinations
    data["approval"] = {**data["approval"], "roe_sha256": roe_digest(data)}
    return data


@pytest.mark.parametrize("dest", [
    {**DESTINATION, "host": "defectdojo.example.com"},
    {**DESTINATION, "ip": "203.0.113.7/32"},
    {**DESTINATION, "ip": "10.99.0.2/32"},                  # un objetivo del laboratorio
    {**DESTINATION, "ip": "10.97.0.0/24"},                  # no es una sola IP
    {**DESTINATION, "port": 0},
    {k: v for k, v in DESTINATION.items() if k != "dd_engagement_id"},
])
def test_destino_fuera_de_la_red_de_herramientas(tmp_path, dest):
    lab = Lab(tmp_path, destinations=[DESTINATION])
    with pytest.raises(RoEError) as exc:
        parse_roe(_roe_data(lab, [dest]))
    assert exc.value.code == "roe_invalid" and "report_destinations" in str(exc.value)


def test_destino_agregado_despues_de_aprobar(tmp_path):
    lab = Lab(tmp_path)
    data = dict(lab.roe.source)
    data["report_destinations"] = [DESTINATION]              # sin recalcular el hash
    with pytest.raises(RoEError) as exc:
        parse_roe(data)
    assert exc.value.code == "roe_tampered"


def test_destino_valido(tmp_path):
    lab = Lab(tmp_path, destinations=[DESTINATION])
    (d,) = lab.roe.report_destinations
    assert (d.host, d.ip, d.port, d.dd_engagement_id) == (DD_HOST, DD_IP, 8080, 3)


def test_token_de_report_solo_alcanza_el_destino(tmp_path):
    lab = Lab(tmp_path, destinations=[DESTINATION])
    token = lab.issuer.issue(lab.roe, Phase.REPORT)
    assert token.allowed_cidrs == (f"{DD_IP}/32",) and token.allowed_domains == (DD_HOST,)
    assert lab.issuer.issue(lab.roe, Phase.VALIDATE).allowed_domains != (DD_HOST,)


@pytest.mark.parametrize("target", ["dvwa.lab.test", "10.99.0.2"])
def test_exportar_hacia_un_objetivo_del_laboratorio(tmp_path, target):
    lab = Lab(tmp_path, destinations=[DESTINATION])
    h = lab.harness()
    token = lab.issuer.issue(lab.roe, Phase.REPORT)
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("report-delivery", EXPORT, target, token, subject="report-v1")
    assert exc.value.reason == "out_of_scope"
    last = lab.audit.entries[-1]
    assert (last["result"], last["reason"], last["phase"]) == ("BLOCKED", "out_of_scope",
                                                               "report")


def test_roe_sin_destinos(tmp_path):
    lab = Lab(tmp_path, destinations=[])
    token = lab.issuer.issue(lab.roe, Phase.REPORT)
    assert token.allowed_cidrs == () and token.allowed_domains == ()
    for target in (DD_HOST, DD_IP, "dvwa.lab.test"):
        with pytest.raises(ScopeViolation) as exc:
            lab.harness().invoke("report-delivery", EXPORT, target, token, subject="report-v1")
        assert exc.value.reason == "out_of_scope"


def test_destino_autorizado_que_resuelve_fuera(tmp_path):
    lab = Lab(tmp_path, destinations=[DESTINATION])
    h = lab.harness(resolver=lambda host: ["10.97.0.30"])
    token = lab.issuer.issue(lab.roe, Phase.REPORT)
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("report-delivery", EXPORT, DD_HOST, token, subject="report-v1")
    assert exc.value.reason == "dns_out_of_scope"
