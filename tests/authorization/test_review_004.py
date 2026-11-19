"""Change 004 · hallazgos del security-reviewer sobre el Harness y el emisor de tokens."""
import time

import pytest

from harness.adapters.common import InvalidTarget
from harness.contracts import (
    AuditLog,
    Guard,
    Harness,
    KillSwitch,
    Phase,
    ScopeViolation,
    normalize_target,
)
from harness.policy_loader import phase_allowlist
from harness.ratelimit import RateLimiter
from harness.roe import parse_roe
from harness.tokens import TokenIssuer
from tests.conftest import TEST_ISSUER, FakeAdapter, act, make_token
from tests.test_roe_and_tokens import NOW, roe_data

LAB = {"dvwa.lab.test": ["10.99.0.3"], "juiceshop.lab.test": ["10.99.0.4"],
       "js.dvwa.lab.test": ["10.99.0.4"]}


def lab_dns(host):
    return LAB.get(host, [])


def _issue(resolver):
    issuer = TokenIssuer(AuditLog(), key=b"k" * 32, resolver=resolver)
    roe = parse_roe(roe_data(exclusions={"hosts": [], "domains": ["juiceshop.lab.test"]}))
    return issuer, issuer.issue(roe, Phase.RECON, now=NOW)


# --- 1. La exclusión por nombre no se evade llegando por la IP ---------------------------

def test_el_token_fija_las_ip_de_los_nombres_excluidos():
    _, token = _issue(lab_dns)
    assert {"juiceshop.lab.test", "10.99.0.4"} <= set(token.excluded)


@pytest.mark.parametrize("target", ["10.99.0.4", "js.dvwa.lab.test"])
def test_host_excluido_por_nombre_no_se_alcanza_por_ip_ni_por_otro_nombre(monkeypatch, target):
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    issuer, token = _issue(lab_dns)
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    audit = AuditLog()
    h = Harness(Guard(phase_allowlist()), audit, {adapter.name: adapter}, KillSwitch(), issuer,
                resolver=lab_dns)
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("recon", act("httpx.probe", Phase.RECON), target, token)
    assert exc.value.reason == "excluded" and adapter.calls == []


def test_nombre_excluido_que_no_resuelve_al_emitir_no_rompe_la_emision():
    _, token = _issue(lambda host: [])
    assert "juiceshop.lab.test" in token.excluded


def test_resolver_que_falla_al_emitir_no_rompe_la_emision():
    def broken(host):
        raise OSError("dns caído")
    _, token = _issue(broken)
    assert "juiceshop.lab.test" in token.excluded


def test_ip_resuelta_fuera_del_laboratorio_no_se_agrega_como_exclusion_rara():
    _, token = _issue(lambda host: ["not-an-ip"])
    assert "not-an-ip" not in token.excluded


# --- 3. Un adaptador que lanza después del OK deja cierre en la bitácora -----------------

class Exploding(FakeAdapter):
    def run(self, action, target, token, addresses):
        raise InvalidTarget("objetivo que la herramienta no acepta")


def test_adaptador_que_lanza_queda_abortado_en_bitacora():
    audit = AuditLog()
    adapter = Exploding("httpx.probe", (Phase.RECON,))
    h = Harness(Guard(phase_allowlist()), audit, {adapter.name: adapter}, KillSwitch(),
                TEST_ISSUER, resolver=lambda host: ["10.0.0.50"])
    out = h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", make_token())
    assert out == {"tool": "httpx.probe", "target": "10.0.0.5", "status": "error",
                   "error": "adapter_error"}
    assert [e["result"] for e in audit.entries[-2:]] == ["OK", "ABORTED"]
    assert audit.entries[-1]["reason"] == "adapter_error"
    audit.verify_integrity()


@pytest.mark.parametrize("name", ["a-.lab.example.test", "-a.lab.example.test",
                                  "a_b.lab.example.test"])
def test_nombres_que_ninguna_herramienta_acepta_no_normalizan(name):
    assert normalize_target(name) is None


# --- 6. Rate limit por IP de destino, en el Harness ---------------------------------------

class FakeClock:
    def __init__(self):
        self.t = 100.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_rate_limit_por_ip_aunque_cambie_el_nombre():
    clock = FakeClock()
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    h = Harness(Guard(phase_allowlist()), AuditLog(), {adapter.name: adapter}, KillSwitch(),
                TEST_ISSUER, resolver=lambda host: ["10.0.0.50"],
                limiter=RateLimiter(5, clock=clock.now, sleep=clock.sleep))
    names = [f"v{i}.lab.example.test" for i in range(7)] + ["10.0.0.50"]
    for name in names:
        h.invoke("recon", act("httpx.probe", Phase.RECON), name, make_token())
    assert clock.t >= 101.0                 # 8 sondeos a la misma IP: hubo que esperar


def test_el_harness_limita_por_defecto_segun_la_politica():
    h = Harness(Guard(phase_allowlist()), AuditLog(), {}, KillSwitch(), TEST_ISSUER)
    assert h.limiter is not None and h.limiter.rate == 5
