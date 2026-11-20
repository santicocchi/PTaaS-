"""Change 010 · authorization: el target del práctico integrador (`phantomcorp`) en el laboratorio."""
import ipaddress
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from demo.checkpoint1 import prepare_roe
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase, ScopeViolation
from harness.policy_loader import phase_allowlist
from harness.roe import RoEError, parse_roe, roe_digest
from harness.tokens import TokenIssuer
from tests.conftest import FakeAdapter, act

ROOT = Path(__file__).resolve().parents[2]
ROE = ROOT / "demo" / "roe-integrador.yaml"
COMPOSE = ROOT / "lab" / "docker-compose.yml"
PROFILES = ROOT / "harness" / "profiles.yaml"
NOW = datetime(2026, 11, 20, 15, 0, tzinfo=UTC)
LAB = {"phantomcorp.lab.test": ["10.99.0.12"], "dvwa.lab.test": ["10.99.0.10"],
       "juiceshop.lab.test": ["10.99.0.11"]}


def _roe():
    return parse_roe(prepare_roe("eng-integrador-1", NOW, template=ROE))


def _rehash(data):
    data["approval"]["roe_sha256"] = roe_digest(data)
    return data


# --- Requirement: Alcance máximo del laboratorio (MODIFIED) --------------------------------

def test_roe_del_integrador_se_acepta():
    roe = _roe()
    assert roe.domains == ("phantomcorp.lab.test",) and roe.cidrs == ("10.99.0.12/32",)
    assert {"dvwa.lab.test", "juiceshop.lab.test"} <= set(roe.excluded)


def test_lab_only_cidrs_no_cambia_y_suma_el_dominio():
    targets = yaml.safe_load(PROFILES.read_text(encoding="utf-8"))["targets"]
    assert targets["lab_only_cidrs"] == ["10.99.0.0/24"]
    assert "phantomcorp.lab.test" in targets["lab_only_domains"]


@pytest.mark.parametrize("scope", [
    {"domains": ["phantomcorp"]},                 # nombre corto de la red del curso
    {"cidrs": ["172.18.0.0/16"]},                 # cyberlab_labnet (red por defecto de Docker)
    {"cidrs": ["172.18.0.2/32"]},
])
def test_nombre_corto_o_red_del_curso_se_rechaza(scope):
    data = prepare_roe("eng-integrador-1", NOW, template=ROE)
    data["scope"] = scope
    with pytest.raises(RoEError) as exc:
        parse_roe(_rehash(data))
    assert "fuera del laboratorio" in " ".join(exc.value.errors)


# --- Requirement: El target del integrador vive solo en la red aislada (ADDED) -------------

def _phantomcorp(compose):
    return compose["services"]["phantomcorp"]


SERVICE_KEYS = {"profiles", "build", "image", "pull_policy", "networks"}


def check_compose(compose):
    svc = _phantomcorp(compose)
    # Allowlist: cualquier otra clave (cap_add, devices, pid, extra_hosts, dns, secrets...) falla.
    assert set(svc) <= SERVICE_KEYS, f"claves no permitidas: {set(svc) - SERVICE_KEYS}"
    assert set(svc["build"]) == {"context"} and svc.get("pull_policy") == "build"
    assert svc.get("profiles") == ["integrador"]
    nets = svc["networks"]
    assert list(nets) == ["lab"], f"phantomcorp solo puede estar en `lab`: {list(nets)}"
    assert nets["lab"]["ipv4_address"] == "10.99.0.12"
    assert nets["lab"]["aliases"] == ["phantomcorp.lab.test"]
    assert compose["networks"]["lab"]["internal"] is True
    lab_cidrs = yaml.safe_load(PROFILES.read_text(encoding="utf-8"))["targets"]["lab_only_cidrs"]
    ip = ipaddress.ip_address(nets["lab"]["ipv4_address"])
    assert any(ip in ipaddress.ip_network(c) for c in lab_cidrs)
    # Las IP fijas de los objetivos quedan fuera del rango dinámico de la red.
    ipam = compose["networks"]["lab"]["ipam"]["config"][0]
    dynamic = ipaddress.ip_network(ipam["ip_range"])
    for name in ("dvwa", "juiceshop", "phantomcorp"):
        fixed = ipaddress.ip_address(compose["services"][name]["networks"]["lab"]["ipv4_address"])
        assert fixed in ipaddress.ip_network(ipam["subnet"]) and fixed not in dynamic, name


def test_servicio_bien_declarado():
    check_compose(yaml.safe_load(COMPOSE.read_text(encoding="utf-8")))


def test_target_conectado_a_la_red_de_herramientas_falla():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    _phantomcorp(compose)["networks"]["tools"] = {}
    with pytest.raises(AssertionError):
        check_compose(compose)


@pytest.mark.parametrize("cambio", [
    lambda s: s.pop("profiles"),
    lambda s: s.__setitem__("ports", ["80:80"]),
    lambda s: s.__setitem__("volumes", ["/var/run/docker.sock:/var/run/docker.sock"]),
    lambda s: s.__setitem__("cap_add", ["NET_ADMIN"]),
    lambda s: s.__setitem__("extra_hosts", ["x:1.2.3.4"]),
    lambda s: s["build"].__setitem__("network", "host"),
    lambda s: s.pop("pull_policy"),
])
def test_target_sin_perfil_o_expuesto_falla(cambio):
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    cambio(_phantomcorp(compose))
    with pytest.raises(AssertionError):
        check_compose(compose)


# --- Requirement: Solo `phantomcorp` en el engagement integrador (ADDED) --------------------

def _harness_and_token(monkeypatch, resolver):
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    issuer = TokenIssuer(AuditLog(), key=b"k" * 32, resolver=resolver)
    token = issuer.issue(_roe(), Phase.RECON, now=NOW)
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    audit = AuditLog()
    h = Harness(Guard(phase_allowlist()), audit, {adapter.name: adapter}, KillSwitch(), issuer,
                resolver=resolver)
    return h, token, adapter, audit


def test_phantomcorp_se_alcanza(monkeypatch):
    h, token, adapter, audit = _harness_and_token(monkeypatch, lambda host: LAB.get(host, []))
    h.invoke("recon", act("httpx.probe", Phase.RECON), "phantomcorp.lab.test", token)
    assert adapter.addresses == [("10.99.0.12",)]
    assert audit.entries[-1]["result"] == "OK"


@pytest.mark.parametrize("target", ["dvwa.lab.test", "juiceshop.lab.test", "10.99.0.10",
                                    "10.99.0.11"])
def test_accion_sobre_dvwa_o_juice_shop_se_bloquea(monkeypatch, target):
    h, token, adapter, audit = _harness_and_token(monkeypatch, lambda host: LAB.get(host, []))
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("recon", act("httpx.probe", Phase.RECON), target, token)
    # Fuera del alcance (/32 y un solo dominio) y, además, excluidos por nombre e IP.
    assert exc.value.reason in {"out_of_scope", "excluded"}
    assert adapter.calls == []
    assert audit.entries[-1]["result"] == "BLOCKED" and audit.entries[-1]["target"] == target


@pytest.mark.parametrize("target", ["dvwa.lab.test", "juiceshop.lab.test", "10.99.0.10",
                                    "10.99.0.11"])
def test_alcance_ampliado_por_error_igual_excluye_dvwa_y_juice_shop(monkeypatch, target):
    """Si alguien amplía el alcance a toda la red, las exclusiones (nombre e IP) prevalecen."""
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    data = prepare_roe("eng-integrador-1", NOW, template=ROE)
    data["scope"] = {"cidrs": ["10.99.0.0/24"],
                     "domains": ["phantomcorp.lab.test", "dvwa.lab.test", "juiceshop.lab.test"]}
    resolver = lambda host: LAB.get(host, [])
    issuer = TokenIssuer(AuditLog(), key=b"k" * 32, resolver=resolver)
    token = issuer.issue(parse_roe(_rehash(data)), Phase.RECON, now=NOW)
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    h = Harness(Guard(phase_allowlist()), AuditLog(), {adapter.name: adapter}, KillSwitch(),
                issuer, resolver=resolver)
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("recon", act("httpx.probe", Phase.RECON), target, token)
    assert exc.value.reason == "excluded" and adapter.calls == []


@pytest.mark.parametrize("capability,phase", [("httpx.probe", Phase.RECON),
                                              ("nmap.service_scan", Phase.RECON)])
def test_nombre_del_integrador_que_resuelve_fuera_del_alcance(monkeypatch, capability, phase):
    h, token, _, audit = _harness_and_token(
        monkeypatch, lambda host: ["10.99.0.50"] if host == "phantomcorp.lab.test" else [])
    adapter = FakeAdapter(capability, (phase,))
    h.tools[capability] = adapter
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("recon", act(capability, phase), "phantomcorp.lab.test", token)
    assert exc.value.reason == "dns_out_of_scope" and adapter.calls == []
    assert audit.entries[-1]["result"] == "BLOCKED"
