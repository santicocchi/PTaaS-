"""El loop A de la demo corre en simulación (adaptadores reales, salidas grabadas)."""
from demo import loop_a
from harness.assets import AssetGraph


def test_loop_a_simulado(tmp_path, capsys):
    assert loop_a.main(["--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "grafo estabilizado" in out and "OK: cadena íntegra" in out
    (db,) = tmp_path.glob("demo-loopa-*.assets.sqlite3")
    graph = AssetGraph.open(db.name.removesuffix(".assets.sqlite3"), tmp_path)
    outside = {a.address: a.reason for a in graph.assets(in_scope=False)}
    assert outside == {"juiceshop.lab.test": "excluded", "cdn.example.com": "out_of_scope",
                       "203.0.113.7": "out_of_scope"}
    assert any(a.address == "http://dvwa.lab.test:80" for a in graph.handoff())


def test_loop_a_lab_sin_laboratorio_no_hace_nada(tmp_path, monkeypatch):
    monkeypatch.setattr(loop_a, "_lab_reachable", lambda: False)
    assert loop_a.main(["--lab", "--out", str(tmp_path)]) == 2
    assert not list(tmp_path.iterdir())
