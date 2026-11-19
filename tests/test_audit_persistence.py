"""Scenarios del delta `audit-log` del change 002: bitácora persistente en SQLite."""
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from harness.audit import AuditIntegrityError, SqliteAuditLog, verify_file
from harness.contracts import Action, Guard, Harness, KillSwitch, KillSwitchEngaged, Phase, Result
from harness.policy_loader import phase_allowlist
from tests.conftest import TEST_ISSUER, FakeAdapter, act, fake_dns, make_token

ROOT = Path(__file__).parents[1]


def _fill(log: SqliteAuditLog, n: int, eng: str = "eng-1") -> None:
    t = make_token(engagement_id=eng)
    for i in range(n):
        log.record("recon", Action(f"a{i}", Phase.RECON), f"10.0.0.{i + 1}", t, Result.OK)


def _raw(path: Path) -> sqlite3.Connection:
    """Acceso directo al archivo, como haría un atacante: sin la capa de acceso."""
    return sqlite3.connect(path)


def _drop_triggers(con: sqlite3.Connection) -> None:
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        con.execute(f'DROP TRIGGER "{name}"')


def _cli_verify(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "harness.audit", "verify", str(path)],
                          cwd=ROOT, capture_output=True, text=True, check=False)


# --- Persistencia por engagement ---------------------------------------------

def test_recuperacion_tras_reinicio(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    _fill(log, 3)
    log.close()
    reabierta = SqliteAuditLog.open("eng-1", tmp_path)
    entries = reabierta.entries
    assert [e["target"] for e in entries] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert entries[0]["prev"] == "GENESIS:eng-1"
    assert verify_file(reabierta.path) is None


def test_dos_engagements_no_comparten_registros(tmp_path):
    a = SqliteAuditLog.open("eng-1", tmp_path)
    b = SqliteAuditLog.open("eng-2", tmp_path)
    _fill(a, 2, "eng-1")
    _fill(b, 1, "eng-2")
    assert a.path != b.path
    assert {e["engagement"] for e in b.entries} == {"eng-2"}
    assert len(b.entries) == 1


@pytest.mark.parametrize("eng", ["../otro", "eng/../../x", "", "ENG 1", "a" * 70])
def test_engagement_id_usado_como_ruta_se_rechaza(tmp_path, eng):
    with pytest.raises(ValueError):
        SqliteAuditLog.open(eng, tmp_path)
    assert list(tmp_path.rglob("*")) == []


def test_record_con_token_de_otro_engagement_se_rechaza(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    with pytest.raises(ValueError):
        log.record("recon", Action("a", Phase.RECON), "10.0.0.1",
                   make_token(engagement_id="eng-2"), Result.OK)
    assert log.entries == []


# --- Append-only -------------------------------------------------------------

@pytest.mark.parametrize("sql", ["UPDATE audit SET target='10.9.9.9' WHERE seq=1",
                                 "DELETE FROM audit WHERE seq=1"])
def test_update_o_delete_por_sql_se_rechaza(tmp_path, sql):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    _fill(log, 2)
    antes = log.entries
    con = _raw(log.path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute(sql)
    con.close()
    assert log.entries == antes


def test_la_capa_de_acceso_no_expone_modificacion():
    publicos = {n for n in dir(SqliteAuditLog) if not n.startswith("_")}
    assert not publicos & {"update", "delete", "remove", "clear", "truncate", "set", "edit"}


# --- Verificación al abrir y bajo demanda ------------------------------------

def test_fila_alterada_en_el_archivo(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    _fill(log, 4)
    log.close()
    con = _raw(log.path)
    _drop_triggers(con)
    con.execute("UPDATE audit SET target='10.9.9.9' WHERE seq=2")
    con.commit(); con.close()
    r = _cli_verify(log.path)
    assert r.returncode == 1
    assert "seq=2" in r.stdout
    with pytest.raises(AuditIntegrityError):
        SqliteAuditLog.open("eng-1", tmp_path)


def test_fila_intermedia_borrada_en_el_archivo(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    _fill(log, 4)
    log.close()
    con = _raw(log.path)
    _drop_triggers(con)
    con.execute("DELETE FROM audit WHERE seq=2")
    con.commit(); con.close()
    assert _cli_verify(log.path).returncode == 1


def test_cadena_integra_verifica_por_cli(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    _fill(log, 3)
    log.close()
    r = _cli_verify(log.path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_inicio_de_cadena_trasplantado(tmp_path):
    origen = SqliteAuditLog.open("eng-1", tmp_path)
    _fill(origen, 3, "eng-1")
    origen.close()
    destino = tmp_path / "eng-2.sqlite3"
    destino.write_bytes(origen.path.read_bytes())       # cadena válida, pero de otro engagement
    assert verify_file(destino) is not None
    assert _cli_verify(destino).returncode == 1


# --- Cadena rota detiene el engagement ---------------------------------------

def _harness(log: SqliteAuditLog) -> tuple[Harness, FakeAdapter]:
    adapter = FakeAdapter("httpx.probe", (Phase.RECON,))
    return Harness(Guard(phase_allowlist()), log, {"httpx.probe": adapter}, KillSwitch(),
                   TEST_ISSUER, resolver=fake_dns), adapter


def test_manipulacion_durante_el_engagement(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    h, adapter = _harness(log)
    t = make_token()
    h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", t)
    h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.6", t)
    con = _raw(log.path)
    _drop_triggers(con)
    con.execute("UPDATE audit SET target='10.0.0.99' WHERE seq=1")
    con.commit(); con.close()
    with pytest.raises(AuditIntegrityError):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.7", t)
    assert adapter.calls == ["10.0.0.5", "10.0.0.6"]


# --- Escrituras concurrentes -------------------------------------------------

def test_cuatro_hilos_escribiendo_50_registros(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    t = make_token()

    def escribir(n: int) -> None:
        for i in range(50):
            log.record(f"agent-{n}", Action("a", Phase.RECON), f"10.0.0.{i + 1}", t, Result.OK)

    hilos = [threading.Thread(target=escribir, args=(n,)) for n in range(4)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    assert len(log.entries) == 200
    assert verify_file(log.path) is None


# --- Kill switch persistente -------------------------------------------------

def test_reinicio_despues_de_abortar(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    h, _ = _harness(log)
    h.kill("eng-1", agent="reviewer")
    log.close()

    reabierta = SqliteAuditLog.open("eng-1", tmp_path)
    h2, adapter = _harness(reabierta)              # proceso nuevo: KillSwitch() limpio
    with pytest.raises(KillSwitchEngaged):
        h2.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", make_token())
    assert adapter.calls == []
    assert reabierta.entries[-1]["result"] == "ABORTED"


# --- Evidencia por referencia ------------------------------------------------

@pytest.mark.parametrize("evidence", [
    "<html>contenido del objetivo</html>",
    "evidence/eng-1/resp.txt",                        # sin hash
    "evidence/eng-1/resp.txt#sha256=xyz",             # hash inválido
])
def test_evidencia_con_contenido_se_rechaza(tmp_path, evidence):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    with pytest.raises(ValueError):
        log.record("validation", Action("a", Phase.RECON), "10.0.0.1", make_token(),
                   Result.OK, evidence=evidence)
    assert log.entries == []


def test_evidencia_por_referencia_se_acepta(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    ref = "evidence/eng-1/resp.txt#sha256=" + "a" * 64
    log.record("validation", Action("a", Phase.RECON), "10.0.0.1", make_token(),
               Result.OK, evidence=ref)
    assert log.entries[-1]["evidence"] == ref
    assert verify_file(log.path) is None


def test_fila_borrada_y_seq_renumerado(tmp_path):
    """El atacante borra una fila y renumera para tapar el hueco: lo detecta `prev`."""
    log = SqliteAuditLog.open("eng-1", tmp_path)
    _fill(log, 4)
    log.close()
    con = _raw(log.path)
    _drop_triggers(con)
    con.execute("DELETE FROM audit WHERE seq=2")
    con.execute("UPDATE audit SET seq=seq-1 WHERE seq>2")
    con.commit(); con.close()
    r = _cli_verify(log.path)
    assert r.returncode == 1 and "seq=2" in r.stdout


def test_registros_de_otro_engagement_reencadenados(tmp_path):
    """Cadena recalculada desde GENESIS:eng-2 pero con registros de eng-1: se rechaza."""
    from harness.audit import genesis
    from harness.contracts import make_entry
    destino = SqliteAuditLog.open("eng-2", tmp_path)
    con = _raw(destino.path)
    prev = genesis("eng-2")
    for i in range(2):
        e = make_entry(prev=prev, engagement="eng-1", agent="recon", action="a",
                       target=f"10.0.0.{i + 1}", phase="recon", result=Result.OK)
        con.execute("INSERT INTO audit (ts, engagement, agent, action, target, phase, result,"
                    " prev, hash) VALUES (?,?,?,?,?,?,?,?,?)",
                    (e["ts"], e["engagement"], e["agent"], e["action"], e["target"],
                     e["phase"], e["result"], e["prev"], e["hash"]))
        prev = e["hash"]
    con.commit(); con.close()
    error = verify_file(destino.path)
    assert error is not None and "otro engagement" in error


# --- Hallazgos del security-reviewer -----------------------------------------

def test_borrado_del_final_durante_el_engagement(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    h, adapter = _harness(log)
    t = make_token()
    for ip in ("10.0.0.5", "10.0.0.6"):
        h.invoke("recon", act("httpx.probe", Phase.RECON), ip, t)
    con = _raw(log.path)
    _drop_triggers(con)
    con.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
    con.commit(); con.close()
    with pytest.raises(AuditIntegrityError):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.7", t)
    assert adapter.calls == ["10.0.0.5", "10.0.0.6"]


def test_cadena_rota_deja_registro_abortado(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    h, _ = _harness(log)
    h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", make_token())
    con = _raw(log.path)
    _drop_triggers(con)
    con.execute("UPDATE audit SET target='10.0.0.99' WHERE seq=1")
    con.commit(); con.close()
    with pytest.raises(AuditIntegrityError):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.6", make_token())
    ultimo = _raw(log.path).execute(
        "SELECT action, result FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    assert ultimo == ("killswitch.engage", "ABORTED")


def test_token_de_otro_engagement_no_ejecuta_sin_registro(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    h, adapter = _harness(log)
    with pytest.raises(ValueError):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5",
                 make_token(engagement_id="eng-2"))
    assert adapter.calls == []


def test_falla_al_registrar_impide_ejecutar(tmp_path, monkeypatch):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    h, adapter = _harness(log)

    def disco_lleno(**_):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(log, "_append", disco_lleno)
    with pytest.raises(sqlite3.OperationalError):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", make_token())
    assert adapter.calls == []


def test_accion_llamada_como_el_kill_switch_no_aborta(tmp_path):
    from harness.contracts import ScopeViolation
    log = SqliteAuditLog.open("eng-1", tmp_path)
    h, _ = _harness(log)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("killswitch.engage", Phase.RECON), "10.0.0.5", make_token())
    log.close()
    h2, adapter = _harness(SqliteAuditLog.open("eng-1", tmp_path))
    h2.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", make_token())
    assert adapter.calls == ["10.0.0.5"]


def test_trigger_reemplazado_de_antemano_se_detecta(tmp_path):
    path = tmp_path / "eng-1.sqlite3"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE audit (seq INTEGER PRIMARY KEY, ts REAL, engagement TEXT, agent"
                " TEXT, action TEXT, target TEXT, phase TEXT, result TEXT, reason TEXT,"
                " evidence TEXT, prev TEXT, hash TEXT)")
    con.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT 1; END")
    con.commit(); con.close()
    with pytest.raises(AuditIntegrityError):
        SqliteAuditLog.open("eng-1", tmp_path)
