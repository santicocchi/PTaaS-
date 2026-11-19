"""Scenarios de la capability `authorization` (+ invariantes I1–I6 del harness)."""
import time

import pytest

from harness.contracts import KillSwitchEngaged, Phase, Result, ScopeViolation
from tests.conftest import act, make_token


def test_activo_fuera_de_alcance_se_bloquea_y_registra(env, token):
    h, _, audit, _, adapters = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.1.5", token)
    assert audit.entries[-1]["result"] == Result.BLOCKED.value
    assert audit.entries[-1]["target"] == "10.0.1.5"
    assert adapters["httpx.probe"].calls == []           # la herramienta nunca corrió


def test_activo_en_alcance_se_ejecuta_y_registra(env, token):
    h, _, audit, _, adapters = env
    out = h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    assert out["ok"] and adapters["httpx.probe"].calls == ["10.0.0.5"]
    assert audit.entries[-1]["result"] == Result.OK.value


def test_dominio_y_subdominio_en_alcance_pero_no_sufijo_enganoso(env, token):
    h, *_ = env
    h.invoke("recon", act("httpx.probe", Phase.RECON), "app.lab.example.test", token)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "evil-lab.example.test", token)


def test_token_vencido_se_bloquea(env):
    h, _, audit, *_ = env
    vencido = make_token(start=time.time() - 100, end=time.time() - 10)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", vencido)
    assert audit.entries[-1]["result"] == "BLOCKED"


def test_token_de_otra_fase_no_habilita_la_accion(env):
    h, *_ = env
    t_analyze = make_token(phase=Phase.ANALYZE)
    with pytest.raises(ScopeViolation):
        h.invoke("analysis", act("poc_catalog.run_parametrized", Phase.VALIDATE), "10.0.0.5", t_analyze)


def test_sondeo_en_fase_correlate_se_bloquea(env):
    h, *_ = env
    t = make_token(phase=Phase.CORRELATE)
    with pytest.raises(ScopeViolation):
        h.invoke("correlation", act("httpx.probe", Phase.RECON), "10.0.0.5", t)


def test_accion_fuera_de_allowlist_de_la_fase(env, token):
    h, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("masscan.sweep", Phase.RECON), "10.0.0.5", token)


def test_accion_destructiva_siempre_bloqueada(env, token):
    h, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON, destructive=True), "10.0.0.5", token)


def test_kill_switch_aborta_sin_ejecutar(env, token):
    h, _, audit, ks, adapters = env
    ks.engage("eng-1")
    with pytest.raises(KillSwitchEngaged):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    assert audit.entries[-1]["result"] == "ABORTED" and adapters["httpx.probe"].calls == []


def test_validacion_sin_aprobacion_queda_pending_hitl(env):
    h, guard, audit, _, adapters = env
    t = make_token(phase=Phase.VALIDATE)
    a = act("poc_catalog.run_parametrized", Phase.VALIDATE, requires_human_approval=True)
    out = h.invoke("validation", a, "10.0.0.5", t)
    assert out["status"] == "PENDING_HITL"
    assert audit.entries[-1]["result"] == "PENDING_HITL" and adapters[a.name].calls == []
    guard.approve(a.name, "10.0.0.5", engagement_id="eng-1", phase=Phase.VALIDATE)
    assert h.invoke("validation", a, "10.0.0.5", t)["ok"]


def test_capability_sin_adaptador_se_bloquea(env, token, monkeypatch):
    h, guard, *_ = env
    guard.phase_allowlist[Phase.RECON].add("naabu.scan")
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("naabu.scan", Phase.RECON), "10.0.0.5", token)


def test_adaptador_no_habilitado_en_la_fase_se_bloquea(env, token):
    h, guard, _, _, adapters = env
    guard.phase_allowlist[Phase.RECON].add("zap.baseline_scan")
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("zap.baseline_scan", Phase.RECON), "10.0.0.5", token)


# --- Change 008: aprobación atada a engagement y fase ------------------------

def _validate_action():
    return act("poc_catalog.run_parametrized", Phase.VALIDATE, requires_human_approval=True)


def test_aprobacion_reutilizada_en_otro_engagement_queda_pending(env):
    h, guard, audit, _, adapters = env
    a = _validate_action()
    guard.approve(a.name, "10.0.0.5", engagement_id="eng-1", phase=Phase.VALIDATE)
    t_eng2 = make_token(phase=Phase.VALIDATE, engagement_id="eng-2")
    out = h.invoke("validation", a, "10.0.0.5", t_eng2)
    assert out["status"] == "PENDING_HITL"
    assert audit.entries[-1]["result"] == "PENDING_HITL"
    assert audit.entries[-1]["engagement"] == "eng-2"
    assert adapters[a.name].calls == []


def test_aprobacion_valida_para_su_engagement_y_fase(env):
    h, guard, audit, _, adapters = env
    a = _validate_action()
    guard.approve(a.name, "10.0.0.5", engagement_id="eng-1", phase=Phase.VALIDATE)
    out = h.invoke("validation", a, "10.0.0.5", make_token(phase=Phase.VALIDATE))
    assert out["ok"] and adapters[a.name].calls == ["10.0.0.5"]
    assert audit.entries[-1]["result"] == "OK"


# --- Change 008: normalización del objetivo ---------------------------------

def test_hostname_con_mayusculas_y_punto_final_decide_igual(env, token):
    h, _, audit, _, adapters = env
    h.invoke("recon", act("httpx.probe", Phase.RECON), "HOST.Lab.Example.Test.", token)
    assert audit.entries[-1]["result"] == "OK"
    assert adapters["httpx.probe"].calls == ["host.lab.example.test"]   # llega normalizado


def test_ipv4_fuera_de_alcance_escrita_como_ipv6_mapeada_se_bloquea(env, token):
    h, _, audit, _, adapters = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "::ffff:10.0.1.5", token)
    assert audit.entries[-1]["result"] == "BLOCKED"
    assert adapters["httpx.probe"].calls == []


def test_ipv4_en_alcance_escrita_como_ipv6_mapeada_se_evalua_como_ipv4(env, token):
    h, _, _, _, adapters = env
    h.invoke("recon", act("httpx.probe", Phase.RECON), "::ffff:10.0.0.5", token)
    assert adapters["httpx.probe"].calls == ["10.0.0.5"]


@pytest.mark.parametrize("target", [
    "http://lab.example.test:80/x",
    "lab.example.test:80",
    "lab.example.test/x",
    "lab example.test",
    "",
])
def test_objetivo_con_puerto_esquema_o_ruta_se_bloquea(env, token, target):
    h, _, audit, _, adapters = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), target, token)
    assert audit.entries[-1]["result"] == "BLOCKED"
    assert adapters["httpx.probe"].calls == []


def test_aprobacion_de_otra_fase_no_habilita(env):
    h, guard, _, _, adapters = env
    a = _validate_action()
    guard.approve(a.name, "dvwa.lab.test", engagement_id="eng-1", phase=Phase.ANALYZE)
    t = make_token(phase=Phase.VALIDATE, domains=("dvwa.lab.test",))
    assert h.invoke("validation", a, "dvwa.lab.test", t)["status"] == "PENDING_HITL"
    assert adapters[a.name].calls == []


@pytest.mark.parametrize("target", ["fe80::1%eth0", "lab.exämple.test", "-x.lab.example.test"])
def test_objetivo_unicode_zona_o_guion_inicial_se_bloquea(env, token, target):
    h, _, audit, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), target, token)
    assert audit.entries[-1]["reason"] == "out_of_scope"


# Scenario de "Token emitido por el harness" (008), implementado en el change 003.
def test_token_fabricado_se_bloquea_como_invalido(env):
    from harness.contracts import ScopeToken
    h, _, audit, *_ = env
    falso = ScopeToken("eng-1", ("0.0.0.0/0",), (), time.time() - 5, time.time() + 600,
                       Phase.RECON)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", falso)
    assert audit.entries[-1]["reason"] == "token_invalid"
