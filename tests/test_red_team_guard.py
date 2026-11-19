"""Red team del guard (día 5): intentos de evasión convertidos en tests.

Cada test es un ataque concreto contra `Harness.invoke`. Los que ya estaban cubiertos por
otros changes se repiten acá a propósito: este archivo es el inventario del red team.
Referencias A1–A10: docs/desafios-extension.md. R11+ son ataques nuevos encontrados acá.
"""
import dataclasses
import threading

import pytest

from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import (
    Action,
    AuditLog,
    Guard,
    Harness,
    KillSwitch,
    Phase,
    ScopeToken,
    ScopeViolation,
)
from harness.policy_loader import phase_allowlist
from tests.conftest import TEST_ISSUER, FakeAdapter, act, fake_dns, make_token


def _blocked(h, audit, adapters, action, target, token, reason=None):
    """El ataque falla: ScopeViolation, registro BLOCKED y ninguna herramienta ejecutada."""
    antes = {k: list(a.calls) for k, a in adapters.items()}
    with pytest.raises(ScopeViolation):
        h.invoke("atacante", action, target, token)
    assert audit.entries[-1]["result"] == "BLOCKED"
    if reason:
        assert audit.entries[-1]["reason"] == reason
    assert {k: a.calls for k, a in adapters.items()} == antes


# --- A1: hostname con mayúsculas, punto final o espacios ---------------------

@pytest.mark.parametrize("target", ["APP.LAB.EXAMPLE.TEST", "app.lab.example.test.",
                                    "  app.lab.example.test  "])
def test_a1_variantes_de_hostname_se_normalizan(env, token, target):
    h, _, _, _, adapters = env
    h.invoke("recon", act("httpx.probe", Phase.RECON), target, token)
    assert adapters["httpx.probe"].calls == ["app.lab.example.test"]


# --- A2: sufijo engañoso -----------------------------------------------------

@pytest.mark.parametrize("target", ["evil-lab.example.test", "lab.example.test.evil.com",
                                    "lab.example.testx", "xlab.example.test"])
def test_a2_sufijo_enganoso(env, token, target):
    h, _, audit, _, adapters = env
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), target, token, "out_of_scope")


# --- A3: IPv6 e IPv4 mapeada -------------------------------------------------

@pytest.mark.parametrize("target", ["::ffff:10.0.1.5", "::ffff:a00:105", "fe80::1", "::1",
                                    "fe80::1%eth0"])
def test_a3_ipv6_fuera_de_alcance(env, token, target):
    h, _, audit, _, adapters = env
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), target, token)


# --- A4: hostname autorizado que resuelve fuera de alcance -------------------

def _harness_con_dns(registros):
    audit = AuditLog()
    adapters = {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))}
    h = Harness(Guard(phase_allowlist()), audit, adapters, KillSwitch(), TEST_ISSUER,
                resolver=lambda host: registros.get(host, []))
    return h, audit, adapters


def test_a4_hostname_que_resuelve_fuera_de_alcance():
    h, audit, adapters = _harness_con_dns({"app.lab.example.test": ["8.8.8.8"]})
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "app.lab.example.test",
             make_token(), "dns_out_of_scope")


def test_a4_hostname_con_una_ip_buena_y_una_mala():
    h, audit, adapters = _harness_con_dns({"app.lab.example.test": ["10.0.0.7", "10.0.1.7"]})
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "app.lab.example.test",
             make_token(), "dns_out_of_scope")


def test_a4_hostname_que_resuelve_a_un_host_excluido():
    h, audit, adapters = _harness_con_dns({"app.lab.example.test": ["10.0.0.1"]})
    sin_firma = dataclasses.replace(make_token(), excluded=("10.0.0.1",))
    tok = dataclasses.replace(sin_firma, mac=TEST_ISSUER._mac(sin_firma))
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "app.lab.example.test", tok,
             "excluded")


def test_a4_hostname_que_no_resuelve_falla_cerrado():
    h, audit, adapters = _harness_con_dns({})
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "app.lab.example.test",
             make_token(), "dns_unresolved")


def test_a4_hostname_que_resuelve_dentro_se_ejecuta():
    h, _, adapters = _harness_con_dns({"app.lab.example.test": ["10.0.0.7"]})
    h.invoke("recon", act("httpx.probe", Phase.RECON), "app.lab.example.test", make_token())
    assert adapters["httpx.probe"].calls == ["app.lab.example.test"]


# --- A5: redirecciones HTTP --------------------------------------------------
# Los adaptadores HTTP reales (httpx, ZAP) llegan en el change 004/005. Queda como
# Requirement de esos changes: el adaptador NO DEBE seguir redirecciones fuera de alcance.


# --- A6: token reutilizado en otra fase o engagement -------------------------

def test_a6_token_de_recon_usado_para_validar(env):
    h, _, audit, _, adapters = env
    _blocked(h, audit, adapters, act("poc_catalog.run_parametrized", Phase.VALIDATE),
             "10.0.0.5", make_token(phase=Phase.RECON), "wrong_phase")


def test_a6_token_firmado_con_otro_engagement_reescrito(env):
    h, _, audit, _, adapters = env
    t = dataclasses.replace(make_token(), engagement_id="eng-2")
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "10.0.0.5", t, "token_invalid")


def test_a6_token_de_otro_engagement_en_bitacora_ajena(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    h = Harness(Guard(phase_allowlist()), log, {"httpx.probe": adapter}, KillSwitch(),
                TEST_ISSUER, resolver=fake_dns)
    with pytest.raises(ValueError):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5",
                 make_token(engagement_id="eng-2"))
    assert adapter.calls == []


# --- A7 y A8 viven en tests/test_roe_and_tokens.py (zonas horarias y CIDR amplio) ----

# --- A9: argumentos inyectados vía target ------------------------------------

@pytest.mark.parametrize("target", ["-oX /tmp/x 10.0.0.5", "--script=vuln", "-sV",
                                    "10.0.0.5;id", "10.0.0.5 && id", "$(id).lab.example.test",
                                    "`id`.lab.example.test", "10.0.0.5\n-oN", "10.0.0.0/24",
                                    "app.lab.example.test/../../etc"])
def test_a9_inyeccion_de_argumentos_por_target(env, token, target):
    h, _, audit, _, adapters = env
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), target, token, "out_of_scope")


# --- A10: escrituras concurrentes en la bitácora ------------------------------

def test_a10_invocaciones_concurrentes_mantienen_la_cadena(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    h = Harness(Guard(phase_allowlist()), log, {"httpx.probe": adapter}, KillSwitch(),
                TEST_ISSUER, resolver=fake_dns)
    t = make_token()

    def atacar(n):
        for i in range(10):
            target = f"10.0.{n % 2}.{i + 1}"          # mitad dentro, mitad fuera de alcance
            try:
                h.invoke(f"a{n}", act("httpx.probe", Phase.RECON), target, t)
            except ScopeViolation:
                pass

    hilos = [threading.Thread(target=atacar, args=(n,)) for n in range(4)]
    for x in hilos:
        x.start()
    for x in hilos:
        x.join()
    assert verify_file(log.path) is None
    assert len([e for e in log.entries if e["result"] == "BLOCKED"]) == 20
    assert len(adapter.calls) == 20


# --- R11: IPv4 en notaciones alternativas -------------------------------------

@pytest.mark.parametrize("target", ["010.0.0.5", "0x0a000005", "167772165", "10.0.5",
                                    "10.1", "0300.0250.0.1"])
def test_r11_ipv4_en_notacion_octal_hex_o_decimal(env, token, target):
    """curl/nmap interpretan '167772165' como 10.0.0.5: el guard no debe aceptarlo como host."""
    h, _, audit, _, adapters = env
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), target, token, "out_of_scope")


# --- R12: homoglifos y punycode -----------------------------------------------

@pytest.mark.parametrize("target", ["аpp.lab.example.test",          # 'а' cirílica
                                    "xn--pp-8cd.lab.example.test.evil",
                                    "app.lab.example.test\u200b"])
def test_r12_homoglifos(env, token, target):
    h, _, audit, _, adapters = env
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), target, token)


# --- R13: saltear el gate humano declarando la acción "sin aprobación" ---------

def test_r13_validacion_sin_flag_de_aprobacion_igual_exige_gate(env):
    """El agente arma la Action: no puede ser quien decide si necesita aprobación."""
    h, _, audit, _, adapters = env
    t = make_token(phase=Phase.VALIDATE)
    a = Action("poc_catalog.run_parametrized", Phase.VALIDATE, requires_human_approval=False)
    out = h.invoke("validation", a, "10.0.0.5", t)
    assert out == {"status": "PENDING_HITL"}
    assert audit.entries[-1]["result"] == "PENDING_HITL"
    assert adapters["poc_catalog.run_parametrized"].calls == []


# --- R14: adaptador destructivo invocado con una Action "no destructiva" ------

def test_r14_adaptador_destructivo_se_bloquea_aunque_la_action_diga_lo_contrario(env, token):
    h, guard, audit, _, adapters = env
    guard.phase_allowlist[Phase.RECON].add("evil.wipe")
    adapters["evil.wipe"] = FakeAdapter("evil.wipe", (Phase.RECON,), destructive=True)
    _blocked(h, audit, adapters, act("evil.wipe", Phase.RECON, destructive=False), "10.0.0.5",
             token, "destructive")


# --- R15: token fabricado con todo internet ----------------------------------

def test_r15_token_fabricado_con_todo_internet(env):
    import time
    h, _, audit, _, adapters = env
    t = ScopeToken("eng-1", ("0.0.0.0/0",), ("test",), time.time() - 5, time.time() + 600,
                   Phase.RECON, mac="0" * 64)
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "8.8.8.8", t, "token_invalid")


# --- R16: kill switch evadido con otro engagement_id -------------------------

def test_r16_kill_switch_no_se_evade_cambiando_el_engagement(env, token):
    from harness.contracts import KillSwitchEngaged
    h, _, audit, ks, adapters = env
    ks.engage("eng-1")
    with pytest.raises(KillSwitchEngaged):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    otro = dataclasses.replace(token, engagement_id="eng-1b")    # sin firma válida
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "10.0.0.5", otro,
             "token_invalid")


# --- Revisión del security-reviewer sobre este change -------------------------

def test_resolver_que_lanza_excepcion_queda_bloqueado_y_registrado():
    def roto(host):
        raise RuntimeError("timeout")
    audit = AuditLog()
    adapters = {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))}
    h = Harness(Guard(phase_allowlist()), audit, adapters, KillSwitch(), TEST_ISSUER,
                resolver=roto)
    _blocked(h, audit, adapters, act("httpx.probe", Phase.RECON), "app.lab.example.test",
             make_token(), "dns_unresolved")


def test_gate_con_fase_mal_escrita_falla_al_cargar_la_politica():
    from harness.policy_loader import hitl_phases, load_policy
    policy = load_policy()
    policy["gates_hitl"] = [{"before": "validte", "approver_role": "reviewer"}]
    with pytest.raises(ValueError, match="validte"):
        hitl_phases(policy)


@pytest.mark.parametrize("valor", [None, 0, "sin atributo"])
def test_adaptador_sin_declarar_destructive_falso_se_bloquea(env, token, valor):
    h, guard, audit, _, adapters = env
    guard.phase_allowlist[Phase.RECON].add("dudoso.scan")
    a = FakeAdapter("dudoso.scan", (Phase.RECON,))
    if valor == "sin atributo":
        del a.destructive
    else:
        a.destructive = valor
    adapters["dudoso.scan"] = a
    _blocked(h, audit, adapters, act("dudoso.scan", Phase.RECON), "10.0.0.5", token,
             "destructive")


def test_kill_switch_activado_durante_la_resolucion_frena_la_accion():
    from harness.contracts import KillSwitchEngaged
    audit = AuditLog()
    ks = KillSwitch()
    adapters = {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))}

    def lento(host):
        ks.engage("eng-1")                 # el reviewer aprieta el botón mientras resuelve
        return ["10.0.0.7"]

    h = Harness(Guard(phase_allowlist()), audit, adapters, ks, TEST_ISSUER, resolver=lento)
    with pytest.raises(KillSwitchEngaged):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "app.lab.example.test", make_token())
    assert audit.entries[-1]["result"] == "ABORTED"
    assert adapters["httpx.probe"].calls == []
