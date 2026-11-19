"""Change 004 · asset-discovery: orquestación del loop A (todo pasa por Harness.invoke)."""
import itertools
from pathlib import Path

import pytest

from harness.adapters.subfinder_adapter import parse_output as subfinder_output
from harness.assets import AssetGraph
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase
from harness.engagement import Engagement
from harness.policy_loader import phase_allowlist
from harness.recon import ReconLoop
from harness.tokens import TokenIssuer
from tests.conftest import TEST_ISSUER, make_token

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "recon"
LAB_DNS = {"dvwa.lab.test": ["10.99.0.3"], "www.dvwa.lab.test": ["10.99.0.3"],
           "api.dvwa.lab.test": ["10.99.0.4"], "juiceshop.lab.test": ["10.99.0.5"]}


def lab_dns(host):
    if host in LAB_DNS:
        return LAB_DNS[host]
    return ["10.99.0.9"] if host.endswith(".dvwa.lab.test") else []


class Scripted:
    def __init__(self, name, script, log):
        self.name, self.script, self.log = name, script, log
        self.allowed_phases, self.destructive = (Phase.RECON,), False
        self.calls = []

    def run(self, action, target, token, addresses):
        self.calls.append(target)
        self.log.append((self.name, target))
        return self.script(target)


def subfinder_lab(target):
    if target == "dvwa.lab.test":
        return {"tool": "subfinder", **subfinder_output((FIX / "subfinder_lab.jsonl").read_text())}
    return {"tool": "subfinder", "status": "ok", "hosts": [], "invalid_lines": 0}


def httpx_ok(target, location=None):
    return {"tool": "httpx", "status": "ok", "invalid_lines": 0, "services": [
        {"url": f"http://{target}:80", "address": "10.99.0.3", "port": 80, "status_code": 200,
         "title": "x", "webserver": "Apache", "tech": ["Apache HTTP Server:2.4.25"],
         "location": location}]}


def nmap_ok(target):
    return {"tool": "nmap", "status": "ok", "invalid_lines": 0, "services": [
        {"address": "10.99.0.3", "port": 80, "protocol": "tcp", "service": "http",
         "tech": "Apache httpd:2.4.25"}]}


def recon_engagement():
    eng = Engagement(roe_valid=True)
    eng.approve("first_active_action")
    eng.advance()
    eng.advance()
    return eng


class Lab:
    def __init__(self, tmp_path, subfinder=subfinder_lab, httpx=httpx_ok, nmap=nmap_ok,
                 issuer=TEST_ISSUER, max_iterations=5, engagement=None):
        self.log = []
        self.audit = AuditLog()
        self.adapters = {
            "subfinder.enum": Scripted("subfinder.enum", subfinder, self.log),
            "httpx.probe": Scripted("httpx.probe", httpx, self.log),
            "nmap.service_scan": Scripted("nmap.service_scan", nmap, self.log),
        }
        self.harness = Harness(Guard(phase_allowlist()), self.audit, self.adapters, KillSwitch(),
                               issuer, resolver=lab_dns)
        self.token = make_token(cidrs=("10.99.0.0/24",),
                                domains=("dvwa.lab.test", "juiceshop.lab.test"),
                                excluded=("juiceshop.lab.test",))
        self.graph = AssetGraph.open("eng-1", tmp_path)
        self.loop = ReconLoop(self.harness, engagement or recon_engagement(), self.graph,
                              self.token, max_iterations=max_iterations)

    def targets(self):
        return {t for _, t in self.log}

    def controls(self, action):
        return [e for e in self.audit.entries if e["action"] == action]


def test_loop_termina_por_grafo_estabilizado(tmp_path):
    lab = Lab(tmp_path)
    result = lab.loop.run()
    assert result.reason == "grafo estabilizado" and result.iterations == 3
    assert lab.targets() == {"dvwa.lab.test", "www.dvwa.lab.test", "api.dvwa.lab.test"}


def test_loop_termina_por_tope(tmp_path):
    counter = itertools.count()
    lab = Lab(tmp_path, max_iterations=3, subfinder=lambda t: {
        "tool": "subfinder", "status": "ok", "invalid_lines": 0,
        "hosts": [f"n{next(counter)}.dvwa.lab.test"]})
    result = lab.loop.run()
    assert result.reason == "tope de iteraciones alcanzado" and result.iterations == 3


def test_pasivo_antes_que_activo_en_cada_iteracion(tmp_path):
    lab = Lab(tmp_path)
    lab.loop.run()
    assert lab.log == [
        ("subfinder.enum", "dvwa.lab.test"),
        ("httpx.probe", "dvwa.lab.test"), ("nmap.service_scan", "dvwa.lab.test"),
        ("subfinder.enum", "api.dvwa.lab.test"), ("subfinder.enum", "www.dvwa.lab.test"),
        ("httpx.probe", "api.dvwa.lab.test"), ("nmap.service_scan", "api.dvwa.lab.test"),
        ("httpx.probe", "www.dvwa.lab.test"), ("nmap.service_scan", "www.dvwa.lab.test"),
    ]


def test_engagement_sin_aprobacion_no_invoca_nada(tmp_path):
    lab = Lab(tmp_path, engagement=Engagement(roe_valid=True))
    result = lab.loop.run()
    assert result.reason == "engagement fuera de RECON" and lab.log == []
    assert lab.audit.entries == []


def test_descubrimientos_fuera_de_alcance_no_llegan_a_ningun_adaptador(tmp_path):
    lab = Lab(tmp_path, httpx=lambda t: httpx_ok(t, "http://203.0.113.7/"))
    lab.loop.run()
    assert not {"juiceshop.lab.test", "otro.ejemplo.org", "203.0.113.7"} & lab.targets()
    out = {a.address: a.reason for a in lab.graph.assets(in_scope=False)}
    assert out == {"juiceshop.lab.test": "excluded", "otro.ejemplo.org": "out_of_scope",
                   "203.0.113.7": "out_of_scope"}
    blocked = {(e["target"], e["result"], e["reason"]) for e in lab.controls("asset.discovered")}
    assert blocked == {("juiceshop.lab.test", "BLOCKED", "excluded"),
                       ("otro.ejemplo.org", "BLOCKED", "out_of_scope"),
                       ("203.0.113.7", "BLOCKED", "out_of_scope")}
    # el filtro del orquestador actuó antes: el Harness nunca vio esos objetivos
    assert not [e for e in lab.audit.entries if e["target"] == "203.0.113.7"
                and e["action"] != "asset.discovered"]


def test_defensa_en_profundidad_el_harness_bloquea_si_el_orquestador_falla(tmp_path):
    lab = Lab(tmp_path, httpx=lambda t: httpx_ok(t, "http://203.0.113.7/"))
    lab.loop._scope_filter = False                    # simula un bug en el orquestador
    lab.loop.run()
    assert "203.0.113.7" not in lab.targets()
    blocked = [e for e in lab.audit.entries if e["target"] == "203.0.113.7"
               and e["result"] == "BLOCKED" and e["reason"] == "out_of_scope"]
    assert {e["action"] for e in blocked} == {"httpx.probe", "nmap.service_scan"}


def test_subfinder_sin_internet_sigue_con_las_semillas(tmp_path):
    lab = Lab(tmp_path, subfinder=lambda t: {"tool": "subfinder", "status": "ok", "hosts": [],
                                              "invalid_lines": 0})
    result = lab.loop.run()
    assert ("httpx.probe", "dvwa.lab.test") in lab.log
    assert ("nmap.service_scan", "dvwa.lab.test") in lab.log
    assert result.reason == "grafo estabilizado"


def test_httpx_con_timeout_no_frena_a_nmap(tmp_path):
    lab = Lab(tmp_path, httpx=lambda t: {"tool": "httpx", "target": t, "status": "error",
                                          "error": "timeout"})
    lab.loop.run()
    assert ("nmap.service_scan", "dvwa.lab.test") in lab.log
    errors = lab.controls("tool.error")
    assert errors and all(e["result"] == "ABORTED" and e["reason"] == "timeout" for e in errors)
    assert errors[0]["target"] == "dvwa.lab.test"


def test_dos_salidas_invalidas_seguidas_escalan_y_la_herramienta_no_se_usa_mas(tmp_path):
    lab = Lab(tmp_path, httpx=lambda t: {"tool": "httpx", "status": "invalid_output",
                                          "services": [], "invalid_lines": 3})
    lab.loop.run()
    assert len(lab.adapters["httpx.probe"].calls) == 2
    (escalated,) = lab.controls("tool.escalated")
    assert escalated["result"] == "PENDING_HITL" and escalated["target"] == "httpx.probe"
    assert len(lab.adapters["nmap.service_scan"].calls) == 3       # nmap sigue


def test_kill_switch_durante_el_loop(tmp_path):
    lab = Lab(tmp_path)

    def nmap_then_kill(target):
        if target == "api.dvwa.lab.test":                 # iteración 2
            lab.harness.kill("eng-1", "operator")
        return nmap_ok(target)

    lab.adapters["nmap.service_scan"].script = nmap_then_kill
    result = lab.loop.run()
    assert result.reason == "abortado: kill switch" and result.handoff == ()
    assert lab.log[-1] == ("nmap.service_scan", "api.dvwa.lab.test")   # nada más corrió
    assert lab.audit.entries[-1]["result"] == "ABORTED"
    assert [e for e in lab.audit.entries if e["result"] == "ABORTED"
            and e["action"] != "killswitch.engage"] == [lab.audit.entries[-1]]  # sin reintentos


def test_token_revocado_detiene_el_loop(tmp_path):
    audit_issuer = TokenIssuer(AuditLog(), key=b"t" * 32)
    lab = Lab(tmp_path, issuer=audit_issuer)
    audit_issuer.revoke("eng-1", by="reviewer")
    result = lab.loop.run()
    assert result.reason == "abortado: token_revoked" and lab.log == []


def test_entrega_a_correlacion(tmp_path):
    lab = Lab(tmp_path, httpx=lambda t: httpx_ok(t, "http://203.0.113.7/"))
    result = lab.loop.run()
    handed = {a.address for a in result.handoff}
    assert "http://dvwa.lab.test:80" in handed and "dvwa.lab.test" in handed   # httpx y nmap
    assert "203.0.113.7" not in handed and all(a.in_scope for a in result.handoff)


def test_cada_invocacion_queda_en_bitacora_con_su_token(tmp_path):
    lab = Lab(tmp_path)
    lab.loop.run()
    invoked = [(e["action"], e["target"]) for e in lab.audit.entries
               if e["result"] == "OK" and e["phase"] == "recon"]
    assert invoked == lab.log


@pytest.mark.parametrize("bad", [0, -1])
def test_tope_invalido(tmp_path, bad):
    with pytest.raises(ValueError):
        Lab(tmp_path, max_iterations=bad)
