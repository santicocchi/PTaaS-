"""Pipeline 005 de la demo en simulación: recon → correlación → análisis, todo por el Harness."""
import sqlite3

from demo import pipeline
from harness.audit import verify_file
from tests.tool_adapters.allowlist_helpers import approved_allowlist, pending_allowlist


def _audit_rows(tmp_path):
    (db,) = [p for p in tmp_path.glob("demo-pipeline-*.sqlite3") if p.name.count(".") == 1]
    with sqlite3.connect(db) as con:
        return db, con.execute("SELECT phase, action, target, result FROM audit").fetchall()


def test_pipeline_simulado_sin_templates_aprobados(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(pipeline, "TEMPLATES", pending_allowlist(tmp_path / "allowlist"))
    assert pipeline.main(["--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "SINTÉTICO" in out and "OK: cadena íntegra" in out
    assert "nuclei: 0 templates aprobados, 6 sin correr" in out
    assert "sin revisor distinto del autor" in out
    assert "CVE-2099-0001" in out and "confirmed" in out
    db, rows = _audit_rows(tmp_path)
    assert verify_file(db) is None
    phases = {r[0] for r in rows}
    assert {"recon", "correlate", "analyze", "control"} <= phases
    analyze = {(a, t) for p, a, t, _ in rows if p == "analyze"}
    assert ("zap.baseline_scan", "dvwa.lab.test") in analyze
    assert ("nuclei.safe_templates", "dvwa.lab.test") in analyze
    assert not [t for p, a, t, _ in rows if p != "control" and "juiceshop" in t
                and a != "subfinder.enum"]


def test_pipeline_simulado_con_templates_aprobados(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(pipeline, "TEMPLATES", approved_allowlist(tmp_path / "allowlist"))
    assert pipeline.main(["--out", str(tmp_path / "out")]) == 0
    out = capsys.readouterr().out
    assert "nuclei: 6 templates aprobados, 0 sin correr" in out
    assert "OK: cadena íntegra" in out


def test_pipeline_simulado_con_la_allowlist_del_repo(tmp_path, capsys):
    assert pipeline.main(["--out", str(tmp_path)]) == 0
    assert "nuclei: 6 templates aprobados, 0 sin correr" in capsys.readouterr().out


def test_pipeline_lab_sin_laboratorio_no_hace_nada(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "_lab_reachable", lambda: False)
    assert pipeline.main(["--lab", "--out", str(tmp_path)]) == 2
    assert not list(tmp_path.iterdir())


def test_zap_simulado_solo_acepta_endpoints_del_adaptador():
    zap = pipeline.SimZap()
    try:
        zap.call("/JSON/ascan/action/scan/", {})
    except AssertionError:
        pass
    else:
        raise AssertionError("SimZap aceptó un endpoint de escaneo activo")
