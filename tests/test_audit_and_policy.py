"""Bitácora hash-encadenada y coherencia policy.yaml ↔ tools.yaml."""
import ipaddress
import time
from pathlib import Path

import pytest
import yaml

from harness.contracts import BLOCK_REASONS, Action, AuditLog, Phase, Result, ScopeViolation
from harness.policy_loader import inconsistencies, load_policy
from tests.conftest import act, make_token


def _fill(audit: AuditLog, n=3):
    for i in range(n):
        audit.record("recon", Action(f"a{i}", Phase.RECON), "10.0.0.5", make_token(), Result.OK)


def _verify(entries) -> bool:
    import hashlib
    import json
    prev = "GENESIS"
    for e in entries:
        body = {k: v for k, v in e.items() if k != "hash"}
        if body["prev"] != prev:
            return False
        if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
            return False
        prev = e["hash"]
    return True


def test_cadena_integra():
    a = AuditLog(); _fill(a)
    assert _verify(a.entries)


def test_alteracion_se_detecta():
    a = AuditLog(); _fill(a)
    a.entries[1]["target"] = "10.9.9.9"
    assert not _verify(a.entries)


def test_borrado_de_registro_se_detecta():
    a = AuditLog(); _fill(a, 4)
    del a.entries[1]
    assert not _verify(a.entries)


def test_policy_y_tools_son_coherentes():
    diff = inconsistencies()
    assert diff["solo_en_policy"] == set() and diff["solo_en_tools"] == set()


def test_policy_prohibe_destructivo_y_fija_topes():
    p = load_policy()
    assert p["limits"]["destructive_actions"] == "forbidden"
    assert p["limits"]["max_loop_iterations"]["validation"] <= 2
    assert p["sandbox"]["persistence"] == "none"


# --- Change 008: motivo del bloqueo ------------------------------------------

def test_bloqueo_por_alcance_registra_motivo(env, token):
    h, _, audit, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.1.5", token)
    assert audit.entries[-1]["reason"] == "out_of_scope"


def test_bloqueo_por_token_vencido_registra_motivo(env):
    h, _, audit, *_ = env
    vencido = make_token(start=time.time() - 100, end=time.time() - 10)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", vencido)
    assert audit.entries[-1]["reason"] == "token_expired"


def test_todo_bloqueo_tiene_un_motivo_del_conjunto_cerrado(env, token):
    h, guard, audit, *_ = env
    guard.phase_allowlist[Phase.RECON].update({"naabu.scan", "zap.baseline_scan"})
    intentos = [
        (act("httpx.probe", Phase.RECON), "10.0.1.5", token, "out_of_scope"),
        (act("httpx.probe", Phase.RECON, destructive=True), "10.0.0.5", token, "destructive"),
        (act("httpx.probe", Phase.RECON), "10.0.0.5", make_token(phase=Phase.ANALYZE), "wrong_phase"),
        (act("masscan.sweep", Phase.RECON), "10.0.0.5", token, "not_allowlisted"),
        (act("naabu.scan", Phase.RECON), "10.0.0.5", token, "no_adapter"),
        (act("zap.baseline_scan", Phase.RECON), "10.0.0.5", token, "adapter_phase"),
    ]
    for a, target, t, esperado in intentos:
        with pytest.raises(ScopeViolation):
            h.invoke("recon", a, target, t)
        assert audit.entries[-1]["reason"] == esperado
    assert {e["reason"] for e in audit.entries} <= BLOCK_REASONS


# --- Change 008: red del laboratorio coherente con la política ---------------

def _lab_network():
    compose = yaml.safe_load((Path(__file__).parents[1] / "lab" / "docker-compose.yml").read_text())
    return compose["networks"]["lab"]


def test_subred_del_lab_fijada_y_dentro_de_la_politica():
    profiles = yaml.safe_load((Path(__file__).parents[1] / "harness" / "profiles.yaml").read_text())
    permitidas = [ipaddress.ip_network(c) for c in profiles["targets"]["lab_only_cidrs"]]
    config = (_lab_network().get("ipam") or {}).get("config") or []
    subredes = [ipaddress.ip_network(c["subnet"]) for c in config if "subnet" in c]
    assert subredes, "lab/docker-compose.yml no fija la subred de la red `lab`"
    for s in subredes:
        assert any(s.subnet_of(p) for p in permitidas), f"{s} fuera de lab_only_cidrs {permitidas}"


def test_red_del_lab_sin_salida_a_internet():
    assert _lab_network().get("internal") is True
