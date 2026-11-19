"""Change 005 · tool-adapters: ZAP por API, modo protegido, alcance por IP y sin escaneo activo."""
import json
from pathlib import Path

import pytest

from harness.adapters.common import InvalidTarget
from harness.adapters.zap_adapter import (
    ENDPOINTS,
    HttpZapClient,
    ZapBaselineScan,
    ZapError,
    parse_alerts,
)
from harness.contracts import Phase
from tests.conftest import act, make_token

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "analysis"
ALERTS = json.loads((FIX / "zap_alerts.json").read_text())


class FakeZap:
    """Registra cada llamada y contesta como ZAP 2.17.0 (respuestas vistas en la prueba real)."""

    def __init__(self, alerts=ALERTS, spider_steps=2, fail_on=None):
        self.calls, self.alerts, self.steps, self.fail_on = [], alerts, spider_steps, fail_on

    def call(self, path, params):
        assert path in ENDPOINTS
        self.calls.append((path, dict(params)))
        if self.fail_on and self.fail_on in path:
            raise ZapError("exec_error")
        if path.endswith("/newContext/"):
            return {"contextId": "1"}
        if path.endswith("/spider/action/scan/"):
            return {"scan": "0"}
        if path.endswith("/spider/view/status/"):
            self.steps -= 1
            return {"status": "100" if self.steps <= 0 else "40"}
        if path.endswith("/recordsToScan/"):
            return {"recordsToScan": "0"}
        if path.endswith("/alerts/"):
            return self.alerts
        return {"Result": "OK"}

    def paths(self):
        return [p for p, _ in self.calls]

    def params(self, suffix):
        return [q for p, q in self.calls if p.endswith(suffix)]


def run(zap, target="dvwa.lab.test", addresses=("10.99.0.2",), ports=(80,), **kw):
    adapter = ZapBaselineScan(zap, ports_of=lambda h: ports, rps=5, sleep=lambda s: None, **kw)
    return adapter.run(act("zap.baseline_scan", Phase.ANALYZE), target,
                       make_token(Phase.ANALYZE), addresses)


def test_ningun_endpoint_de_escaneo_activo():
    assert not [e for e in ENDPOINTS if "/ascan/" in e or "/fuzz" in e or "/bruteforce" in e]


def test_el_cliente_rechaza_endpoints_fuera_de_la_lista():
    client = HttpZapClient("http://10.97.0.20:8080", "k")
    with pytest.raises(ValueError):
        client.call("/JSON/ascan/action/scan/", {"url": "http://10.99.0.2/"})


def test_secuencia_completa_con_ip_fijada_y_host():
    zap = FakeZap()
    out = run(zap)
    assert out["status"] == "ok"
    assert zap.params("/setMode/") == [{"mode": "protect"}]
    (inc,) = zap.params("/includeInContext/")
    assert inc["regex"] == r"^http://10\.99\.0\.2(:80)?/.*"
    (rule,) = zap.params("/replacer/action/addRule/")
    assert (rule["matchType"], rule["matchString"], rule["replacement"]) == (
        "REQ_HEADER", "Host", "dvwa.lab.test")
    (rl,) = zap.params("/addRateLimitRule/")
    assert rl["requestsPerSecond"] == "5" and rl["matchString"] == "10.99.0.2"
    (scan,) = zap.params("/spider/action/scan/")
    assert scan["url"] == "http://10.99.0.2/" and scan["subtreeOnly"] == "true"
    assert scan["contextName"] == inc["contextName"]
    assert zap.params("/setOptionThreadCount/") == [{"Integer": "1"}]
    assert zap.params("/core/view/alerts/") == [{"baseurl": "http://10.99.0.2/"}]   # con barra
    # limpieza al final, con sesión nueva para no retener datos del objetivo
    assert zap.paths()[-5:] == ["/JSON/spider/action/stop/",
                                "/JSON/context/action/removeContext/",
                                "/JSON/network/action/removeRateLimitRule/",
                                "/JSON/replacer/action/removeRule/",
                                "/JSON/core/action/newSession/"]
    assert zap.params("/spider/action/stop/") == [{"scanId": "0"}]


def test_sesion_nueva_antes_de_todo():
    """Revisión 005, M1: las alertas de corridas anteriores no se atribuyen a este host."""
    zap = FakeZap()
    run(zap)
    assert zap.paths()[0] == "/JSON/core/action/newSession/"
    assert zap.params("/newSession/")[0]["overwrite"] == "true"


def test_spider_sin_formularios_antes_de_escanear():
    """Revisión 005, B2: ZAP envía formularios (también POST) por defecto; acá no."""
    zap = FakeZap()
    run(zap)
    paths = zap.paths()
    scan = paths.index("/JSON/spider/action/scan/")
    for opt in ("setOptionProcessForm", "setOptionPostForm"):
        i = paths.index(f"/JSON/spider/action/{opt}/")
        assert i < scan and zap.params(f"/{opt}/") == [{"Boolean": "false"}]


def test_reglas_de_host_huerfanas_se_borran():
    """Revisión 005, M5: una corrida cortada no deja su regla de Host global viva."""
    class Leftover(FakeZap):
        def call(self, path, params):
            if path.endswith("/replacer/view/rules/"):
                self.calls.append((path, dict(params)))
                return {"rules": [{"description": "ptaas-viejo"},
                                  {"description": "Remove CSP"}]}
            return super().call(path, params)

    zap = Leftover()
    run(zap)
    removed = [q["description"] for q in zap.params("/replacer/action/removeRule/")]
    assert "ptaas-viejo" in removed and "Remove CSP" not in removed


def test_la_limpieza_sigue_aunque_un_paso_falle():
    class Flaky(FakeZap):
        def call(self, path, params):
            if path.endswith("/removeContext/"):
                self.calls.append((path, dict(params)))
                raise ConnectionResetError("corte")
            return super().call(path, params)

    zap = Flaky()
    run(zap)
    assert zap.paths()[-1] == "/JSON/core/action/newSession/"


def test_puerto_no_estandar_e_ip_como_objetivo():
    zap = FakeZap(alerts={"alerts": []})
    run(zap, target="10.99.0.2", ports=(8080,))
    (inc,) = zap.params("/includeInContext/")
    assert inc["regex"] == r"^http://10\.99\.0\.2:8080/.*"
    assert zap.params("/replacer/action/addRule/") == []       # sin nombre no hay Host


def test_alertas_validadas_y_deduplicadas():
    alerts, invalid = parse_alerts("dvwa.lab.test", "10.99.0.2", 80, ALERTS["alerts"])
    assert invalid == 0 and len(alerts) == 5                    # la 10038 venía repetida
    csp = next(a for a in alerts if a["plugin_id"] == "10038")
    assert csp["cwe"] == "CWE-693" and csp["confidence"] == "High"
    assert csp["url"] == "http://dvwa.lab.test:80/"
    comments = next(a for a in alerts if a["plugin_id"] == "10027")
    assert comments["cwe"] == "unknown"


@pytest.mark.parametrize("alert", [
    {"url": "http://203.0.113.7/"},                             # otra IP
    {"url": "http://10.99.0.2:8080/"},                          # otro puerto
    {"url": "https://10.99.0.2/"},
    {"url": "http://dvwa.lab.test/"},                           # por nombre: no es lo que pedimos
    {"risk": "Critical"}, {"confidence": "Seguro"}, {"pluginId": "x1"}, {"cweid": "abc"},
])
def test_alerta_que_no_corresponde_se_descarta(alert):
    base = {"pluginId": "10038", "alert": "x", "risk": "Medium", "confidence": "High",
            "cweid": "693", "url": "http://10.99.0.2/"}
    alerts, invalid = parse_alerts("dvwa.lab.test", "10.99.0.2", 80, [{**base, **alert}])
    assert alerts == [] and invalid == 1


def test_alertas_que_no_son_lista():
    assert parse_alerts("dvwa.lab.test", "10.99.0.2", 80, "x") == ([], 1)


def test_sin_clave_de_api_no_se_manda_nada(monkeypatch):
    monkeypatch.delenv("PTAAS_ZAP_API_KEY", raising=False)
    out = ZapBaselineScan(ports_of=lambda h: (80,), rps=5).run(
        act("zap.baseline_scan", Phase.ANALYZE), "dvwa.lab.test", make_token(Phase.ANALYZE),
        ("10.99.0.2",))
    assert out["status"] == "error" and out["error"] == "exec_error"


def test_zap_que_no_responde_es_error_tipado_y_limpia():
    zap = FakeZap(fail_on="/spider/action/scan/")
    out = run(zap)
    assert out == {"tool": "zap", "target": "dvwa.lab.test", "status": "error",
                   "error": "exec_error"}
    assert "/JSON/context/action/removeContext/" in zap.paths()


def test_spider_que_no_termina_es_timeout():
    t = [0.0]

    def clock():
        t[0] += 100
        return t[0]

    zap = FakeZap(spider_steps=10**6)
    out = run(zap, clock=clock)
    assert out["error"] == "timeout"
    assert "/JSON/spider/action/stop/" in zap.paths()


@pytest.mark.parametrize(("addresses", "ports"), [((), (80,)), (("dvwa.lab.test",), (80,)),
                                                  (("10.99.0.2",), (0,)),
                                                  (("10.99.0.2",), ())])
def test_entradas_invalidas(addresses, ports):
    with pytest.raises(InvalidTarget):
        run(FakeZap(), addresses=addresses, ports=ports)


def test_url_como_objetivo_se_rechaza():
    with pytest.raises(InvalidTarget):
        run(FakeZap(), target="http://dvwa.lab.test/")


def test_cliente_http_traduce_errores(monkeypatch):
    client = HttpZapClient("http://127.0.0.1:9", "k", timeout_s=1)   # puerto cerrado
    with pytest.raises(ZapError) as exc:
        client.call("/JSON/core/view/alerts/", {"baseurl": "http://10.99.0.2"})
    assert exc.value.kind == "exec_error"


def test_cliente_http_manda_la_clave_en_un_encabezado(monkeypatch):
    """Revisión 005, M2: la clave nunca va en la URL (logs de ZAP, excepciones)."""
    seen = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b'{"Result": "OK"}'

    client = HttpZapClient("http://10.97.0.20:8080", "secreta")

    def fake_open(req, timeout):
        seen["url"], seen["key"] = req.full_url, req.get_header("X-zap-api-key")
        return Resp()

    monkeypatch.setattr(client._opener, "open", fake_open)
    client.call("/JSON/core/action/setMode/", {"mode": "protect"})
    assert "secreta" not in seen["url"] and seen["key"] == "secreta"
    assert not any(type(h).__name__ == "HTTPRedirectHandler" for h in client._opener.handlers)


@pytest.mark.parametrize("url,inside", [
    ("http://10.99.0.2/login.php", True), ("http://10.99.0.2:80/x", True),
    ("http://203.0.113.7/", False), ("http://10.99.0.20/", False),
    ("http://10.99.0.2.evil.test/", False), ("http://10.99.0.2:8080/", False),
    ("https://10.99.0.2/", False), ("http://x@10.99.0.2/", False),
])
def test_enlace_a_otro_host_queda_fuera_del_contexto(url, inside):
    """Scenario «enlace a otro host»: el spider solo sigue lo que entra en el contexto."""
    import re

    zap = FakeZap(alerts={"alerts": []})
    run(zap)
    (inc,) = zap.params("/includeInContext/")
    assert bool(re.match(inc["regex"], url)) is inside
