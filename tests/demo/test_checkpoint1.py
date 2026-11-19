"""La demo del Checkpoint 1 sigue andando (modo simulación: no envía tráfico)."""
import sqlite3

from demo import checkpoint1
from harness.audit import verify_file


def test_demo_simulada_bloquea_registra_y_detecta_manipulacion(tmp_path, capsys):
    assert checkpoint1.main(["--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out

    for reason in ("out_of_scope", "excluded", "wrong_phase", "not_allowlisted",
                   "token_invalid", "dns_out_of_scope", "phase_not_in_roe", "roe_tampered"):
        assert reason in out, reason
    assert "EN ESPERA" in out and "kill switch activo" in out
    assert "OK: cadena íntegra" in out and "CADENA ROTA" in out

    (log,) = tmp_path.glob("demo-cp1-*.sqlite3")
    assert verify_file(log) is None                         # la original quedó íntegra
    assert verify_file(tmp_path / "manipulada" / log.name) is not None
    with sqlite3.connect(log) as con:
        results = [r for (r,) in con.execute("SELECT result FROM audit ORDER BY seq")]
    # Solo se ejecutaron el recon permitido y la verificación aprobada.
    executed = [r for r in results if r == "OK"]
    assert len(executed) == 4       # 2 emisiones de token + 2 acciones
    assert results[-2:] == ["ABORTED", "ABORTED"]          # kill switch, también tras reiniciar


def test_demo_lab_sin_laboratorio_no_hace_nada(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(checkpoint1, "_lab_reachable", lambda: False)
    assert checkpoint1.main(["--lab", "--out", str(tmp_path)]) == 2
    assert not list(tmp_path.iterdir())
    assert "runner" in capsys.readouterr().err
