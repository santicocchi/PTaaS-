"""Change 004 · authorization: la herramienta usa la IP que validó el Harness (DNS rebinding)."""
import inspect

from harness.adapters.nmap_adapter import NmapServiceScan
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase
from harness.policy_loader import phase_allowlist
from tests.conftest import TEST_ISSUER, FakeAdapter, act, make_token


class RebindingDNS:
    """Contesta una IP del alcance la primera vez y una de afuera después."""

    def __init__(self):
        self.calls = 0

    def __call__(self, host):
        self.calls += 1
        return ["10.0.0.50"] if self.calls == 1 else ["8.8.8.8"]


def _harness(adapter, resolver):
    return Harness(Guard(phase_allowlist()), AuditLog(), {adapter.name: adapter}, KillSwitch(),
                   TEST_ISSUER, resolver=resolver)


def test_rebinding_el_adaptador_recibe_la_ip_validada_y_no_se_vuelve_a_resolver():
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    dns = RebindingDNS()
    _harness(adapter, dns).invoke("recon", act("httpx.probe", Phase.RECON), "app.lab.example.test",
                                  make_token())
    assert adapter.calls == ["app.lab.example.test"] and adapter.addresses == [("10.0.0.50",)]
    assert dns.calls == 1


def test_nmap_escanea_la_ip_validada_y_no_el_nombre():
    seen = []
    nmap = NmapServiceScan(runner=lambda argv, t: seen.append(argv) or "")
    _harness(nmap, RebindingDNS()).invoke("recon", act("nmap.service_scan", Phase.RECON),
                                          "app.lab.example.test", make_token())
    assert seen[0][-1] == "10.0.0.50" and "app.lab.example.test" not in seen[0]


def test_objetivo_ip_no_consulta_el_resolver():
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    dns = RebindingDNS()
    _harness(adapter, dns).invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5",
                                  make_token())
    assert adapter.addresses == [("10.0.0.5",)] and dns.calls == 0


def test_ip_resuelta_se_normaliza_antes_de_pasarla():
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    _harness(adapter, lambda h: ["::ffff:10.0.0.9", "10.0.0.8"]).invoke(
        "recon", act("httpx.probe", Phase.RECON), "app.lab.example.test", make_token())
    assert adapter.addresses == [("10.0.0.8", "10.0.0.9")]


ADAPTERS = [NmapServiceScan, NucleiSafeTemplates, FakeAdapter]


def test_contrato_todo_adaptador_recibe_addresses():
    from harness.adapters import registry
    for cls in [*ADAPTERS, *registry.ADAPTER_CLASSES]:
        params = inspect.signature(cls.run).parameters
        assert "addresses" in params, f"{cls.__name__}.run no recibe addresses"
