import dataclasses
import time

import pytest

from harness.contracts import Action, AuditLog, Guard, Harness, KillSwitch, Phase, ScopeToken
from harness.policy_loader import phase_allowlist
from harness.tokens import TokenIssuer

# Emisor de prueba con clave fija. Los tests firman tokens sin pasar por un RoE usando el
# método privado `_mac`: eso vive solo acá, no en el código de producción.
TEST_ISSUER = TokenIssuer(AuditLog(), key=b"t" * 32)


def _sign(**fields) -> ScopeToken:
    unsigned = ScopeToken(**fields)
    return dataclasses.replace(unsigned, mac=TEST_ISSUER._mac(unsigned))


class FakeAdapter:
    def __init__(self, name, phases, destructive=False):
        self.name, self.allowed_phases, self.destructive = name, phases, destructive
        self.calls = []
        self.addresses = []

    def run(self, action, target, token, addresses):
        self.calls.append(target)
        self.addresses.append(addresses)
        return {"ok": True, "target": target}


def fake_dns(host: str) -> list[str]:
    """DNS de prueba: todo hostname resuelve a una IP dentro del alcance por defecto."""
    return ["10.0.0.50"]


def make_token(phase=Phase.RECON, cidrs=("10.0.0.0/24",), domains=("lab.example.test",),
               start=None, end=None, engagement_id="eng-1", excluded=()):
    now = time.time()
    return _sign(
        engagement_id=engagement_id, allowed_cidrs=cidrs, allowed_domains=domains,
        window_start=now - 5 if start is None else start,
        window_end=now + 600 if end is None else end, phase=phase, excluded=excluded)


@pytest.fixture
def token():
    return make_token()


@pytest.fixture
def env():
    guard = Guard(phase_allowlist())
    audit = AuditLog()
    ks = KillSwitch()
    adapters = {
        "httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,)),
        "zap.baseline_scan": FakeAdapter("zap.baseline_scan", (Phase.ANALYZE,)),
        "poc_catalog.run_parametrized": FakeAdapter("poc_catalog.run_parametrized",
                                                    (Phase.VALIDATE,)),
    }
    return Harness(guard, audit, adapters, ks, TEST_ISSUER, resolver=fake_dns), guard, audit, ks, adapters


def act(name, phase, **kw):
    return Action(name, phase, **kw)


def engagement_in(state):
    """Engagement aprobado y avanzado hasta `state` (pasa por el gate first_active_action)."""
    from harness.engagement import Engagement

    e = Engagement(roe_valid=True)
    e.approve("first_active_action")
    while e.state != state:
        e.advance()
    return e
