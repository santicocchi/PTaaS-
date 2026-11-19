"""Change 005 · tool-adapters: cve.lookup, epss.lookup y cwe.map leen snapshots y grafo, sin red."""
import socket

import pytest

from harness.contracts import Phase
from tests.conftest import act
from tests.correlation.helpers import CLEAN_TWO, Lab

DATA = ("cve.lookup", "epss.lookup", "cwe.map")


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("una capability de datos abrió una conexión")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def test_las_tres_capabilities_responden_con_la_red_bloqueada(tmp_path, no_network):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    out = {c: lab.harness.invoke("x", act(c, Phase.CORRELATE), "dvwa.lab.test", lab.token)
           for c in DATA}
    assert all(o["status"] == "ok" for o in out.values())
    assert {m["cve"] for m in out["cve.lookup"]["matches"]} == {"CVE-2099-0001",
                                                                "CVE-2099-0002"}
    assert out["epss.lookup"]["epss"] == {"CVE-2099-0001": 0.42, "CVE-2099-0002": None}
    assert out["cwe.map"]["attack"] == {"CWE-22": "T1190"}


@pytest.mark.parametrize("capability", DATA)
def test_solo_se_usan_en_correlate(capability):
    from harness.adapters.registry import ADAPTER_CLASSES

    (cls,) = [c for c in ADAPTER_CLASSES if getattr(c, "name", "") == capability]
    assert cls.allowed_phases == (Phase.CORRELATE,) and cls.destructive is False


@pytest.mark.parametrize("capability", DATA)
def test_feed_alterado_responde_no_disponible(tmp_path, capability):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    (lab.feeds_dir / "nvd.json").write_text("{}")
    out = lab.harness.invoke("x", act(capability, Phase.CORRELATE), "dvwa.lab.test", lab.token)
    assert out["status"] == "unavailable" and out["feed_error"] == "hash_mismatch:nvd.json"
