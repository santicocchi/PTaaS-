"""Change 004 · asset-discovery: grafo de activos persistido, append-only y versionado."""
import sqlite3

import pytest

from harness.assets import AssetGraph, asset_id
from harness.schemas import SchemaError


@pytest.fixture
def graph(tmp_path):
    return AssetGraph.open("eng-1", tmp_path)


def test_activo_sin_herramienta_de_origen_se_rechaza(graph):
    with pytest.raises(SchemaError):
        graph.add("domain", "dvwa.lab.test", source_tool="", iteration=1)


@pytest.mark.parametrize(("kind", "address"), [
    ("subnet", "10.99.0.0/24"), ("domain", "-oN x"), ("ip", "dvwa.lab.test"),
    ("http_service", "ftp://dvwa.lab.test:21"), ("domain", "10.99.0.3")])
def test_tipo_o_direccion_invalidos_se_rechazan(graph, kind, address):
    with pytest.raises(SchemaError):
        graph.add(kind, address, source_tool="httpx", iteration=1)


def test_el_mismo_activo_dos_veces_cuenta_una(graph):
    first = graph.add("domain", "DVWA.lab.test.", source_tool="subfinder", iteration=1)
    second = graph.add("domain", "dvwa.lab.test", source_tool="httpx", iteration=2)
    assert first is not None and second is None
    assert [a.address for a in graph.assets()] == ["dvwa.lab.test"]
    assert graph.new_in(2) == []


def test_id_determinista():
    assert asset_id("domain", "dvwa.lab.test") == asset_id("domain", "dvwa.lab.test")
    assert asset_id("domain", "dvwa.lab.test") != asset_id("ip", "10.99.0.3")


def test_tecnologia_nueva_no_es_activo_nuevo(graph):
    a = graph.add("http_service", "http://dvwa.lab.test:80", source_tool="httpx", iteration=1)
    assert graph.add_tech(a.id, "Apache HTTP Server:2.4.25", source_tool="httpx", iteration=2)
    assert not graph.add_tech(a.id, "Apache HTTP Server:2.4.25", source_tool="nmap", iteration=2)
    assert graph.new_in(2) == []
    (svc,) = graph.assets()
    assert svc.technologies == ("Apache HTTP Server:2.4.25",)


def test_reinicio_entre_iteraciones(tmp_path):
    g = AssetGraph.open("eng-1", tmp_path)
    for host in ("a.lab.test", "b.lab.test", "c.lab.test"):
        g.add("domain", host, source_tool="subfinder", iteration=1)
    g.close()
    again = AssetGraph.open("eng-1", tmp_path)
    assert len(again.assets()) == 3 and again.last_iteration() == 1


def test_intento_de_modificar_el_grafo(graph):
    a = graph.add("domain", "dvwa.lab.test", source_tool="roe", iteration=0)
    graph.add_tech(a.id, "Apache", source_tool="httpx", iteration=1)   # los triggers necesitan filas
    con = sqlite3.connect(graph.path)
    for sql in ("UPDATE assets SET in_scope = 0", "DELETE FROM assets",
                "UPDATE asset_tech SET tech = 'x'", "DELETE FROM asset_tech"):
        with pytest.raises(sqlite3.DatabaseError):
            con.execute(sql)
    con.close()


def test_fuera_de_alcance_queda_con_motivo(graph):
    graph.add("ip", "203.0.113.7", source_tool="httpx", iteration=1, in_scope=False,
              reason="out_of_scope")
    (a,) = graph.assets()
    assert a.in_scope is False and a.reason == "out_of_scope"
    assert graph.assets(in_scope=True) == []


def test_entrega_a_correlacion_solo_en_alcance_y_con_version(graph):
    svc = graph.add("http_service", "http://dvwa.lab.test:80", source_tool="httpx", iteration=1)
    graph.add_tech(svc.id, "Apache HTTP Server:2.4.25", source_tool="httpx", iteration=1)
    plain = graph.add("http_service", "http://juiceshop.lab.test:3000", source_tool="httpx",
                      iteration=1)
    graph.add_tech(plain.id, "Express", source_tool="httpx", iteration=1)
    out = graph.add("ip", "203.0.113.7", source_tool="nmap", iteration=1, in_scope=False,
                    reason="out_of_scope")
    graph.add_tech(out.id, "nginx:1.2.3", source_tool="nmap", iteration=1)
    assert [a.address for a in graph.handoff()] == ["http://dvwa.lab.test:80"]


def test_engagement_id_invalido(tmp_path):
    with pytest.raises(ValueError):
        AssetGraph.open("../x", tmp_path)
