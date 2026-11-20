"""Bitácora persistente: SQLite append-only, un archivo por engagement (change 002).

Uso por CLI:
    python -m harness.audit verify <archivo.sqlite3>
Sale con 0 si la cadena está íntegra y con 1 si no, indicando el primer registro roto.
"""
from __future__ import annotations

import re
import sqlite3
import sys
import threading
from pathlib import Path
from typing import Any

from harness.contracts import (
    KILLSWITCH_ACTION,
    Action,
    AuditIntegrityError,
    Entry,
    Result,
    ScopeToken,
    make_entry,
    phase_label,
    verify_chain,
)

__all__ = ["AuditIntegrityError", "SqliteAuditLog", "verify_file"]

ENGAGEMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_COLUMNS = ("seq", "ts", "engagement", "agent", "action", "target", "phase",
            "result", "reason", "evidence", "prev", "hash")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
  seq        INTEGER PRIMARY KEY,
  ts         REAL    NOT NULL,
  engagement TEXT    NOT NULL,
  agent      TEXT    NOT NULL,
  action     TEXT    NOT NULL,
  target     TEXT    NOT NULL,
  phase      TEXT    NOT NULL,
  result     TEXT    NOT NULL CHECK (result IN ('OK','BLOCKED','PENDING_HITL','ABORTED')),
  reason     TEXT,
  evidence   TEXT,
  prev       TEXT    NOT NULL,
  hash       TEXT    NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'append-only: DELETE prohibido'); END;
"""


def genesis(engagement_id: str) -> str:
    return f"GENESIS:{engagement_id}"


def _row_to_entry(row: tuple[Any, ...]) -> Entry:
    entry = dict(zip(_COLUMNS, row, strict=True))
    for optional in ("reason", "evidence"):
        if entry[optional] is None:
            del entry[optional]
    return entry


def _read_entries(con: sqlite3.Connection) -> list[Entry]:
    rows = con.execute(f"SELECT {', '.join(_COLUMNS)} FROM audit ORDER BY seq").fetchall()
    return [_row_to_entry(r) for r in rows]


def verify_file(path: Path) -> str | None:
    """None si la bitácora es íntegra. El engagement esperado sale del nombre del archivo."""
    path = Path(path)
    if not path.is_file():
        return f"no existe {path}"
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        entries = _read_entries(con)
    except sqlite3.DatabaseError as exc:
        return f"no es una bitácora válida: {exc}"
    finally:
        con.close()
    return verify_chain(entries, genesis(path.stem), engagement=path.stem)


class SqliteAuditLog:
    """Bitácora append-only en SQLite. No expone operaciones de modificación ni borrado."""

    def __init__(self, engagement_id: str, path: Path) -> None:
        self.engagement_id = engagement_id
        self.path = path
        self._local = threading.local()
        self._anchor_lock = threading.Lock()
        self._anchor: tuple[int, str] | None = None   # (cantidad, último hash) ya verificados

    @classmethod
    def open(cls, engagement_id: str, base_dir: Path | str = "audit") -> SqliteAuditLog:
        if not ENGAGEMENT_ID_RE.match(engagement_id):
            raise ValueError(f"engagement_id inválido: {engagement_id!r}")
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        log = cls(engagement_id, base / f"{engagement_id}.sqlite3")
        con = log._con()
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(_SCHEMA)
        log._check_triggers(con)
        log.verify_integrity()                  # se verifica al abrir
        return log

    @staticmethod
    def _check_triggers(con: sqlite3.Connection) -> None:
        """`IF NOT EXISTS` no reemplaza un trigger previo: se comprueba que sea el nuestro."""
        found = dict(con.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'"
        ).fetchall())
        for name in ("audit_no_update", "audit_no_delete"):
            if "RAISE(ABORT, 'append-only" not in (found.get(name) or ""):
                raise AuditIntegrityError(f"trigger {name} ausente o alterado")

    # -- conexión por hilo -----------------------------------------------------
    def _con(self) -> sqlite3.Connection:
        con: sqlite3.Connection | None = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            self._local.con = con
        return con

    def close(self) -> None:
        con = getattr(self._local, "con", None)
        if con is not None:
            con.close()
            self._local.con = None

    # -- escritura -------------------------------------------------------------
    def _append(self, **fields: object) -> Entry:
        con = self._con()
        con.execute("BEGIN IMMEDIATE")          # lock de escritura: nadie toma el mismo prev
        try:
            last = con.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last[0] if last else genesis(self.engagement_id)
            entry = make_entry(prev=prev, **fields)  # type: ignore[arg-type]
            con.execute(
                f"INSERT INTO audit ({', '.join(_COLUMNS[1:])}) "
                f"VALUES ({', '.join('?' * (len(_COLUMNS) - 1))})",
                tuple(entry.get(c) for c in _COLUMNS[1:]),
            )
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        seq = con.execute("SELECT seq FROM audit WHERE hash = ?", (entry["hash"],)).fetchone()[0]
        with self._anchor_lock:
            if self._anchor is None or seq > self._anchor[0]:
                self._anchor = (seq, entry["hash"])
        return entry

    def record(self, agent: str, action: Action, target: str, token: ScopeToken,
               result: Result, reason: str | None = None,
               evidence: str | None = None) -> Entry:
        if token.engagement_id != self.engagement_id:
            raise ValueError("el token es de otro engagement")
        return self._append(engagement=self.engagement_id, agent=agent, action=action.name,
                            target=target, phase=phase_label(token), result=result,
                            reason=reason, evidence=evidence)

    def record_control(self, engagement_id: str, agent: str, action: str, target: str,
                       result: Result, reason: str | None = None,
                       evidence: str | None = None) -> Entry:
        if engagement_id != self.engagement_id:
            raise ValueError("registro de control de otro engagement")
        return self._append(engagement=engagement_id, agent=agent, action=action,
                            target=target, phase="control", result=result, reason=reason,
                            evidence=evidence)

    def record_kill(self, engagement_id: str, agent: str) -> Entry:
        return self.record_control(engagement_id, agent, KILLSWITCH_ACTION, engagement_id,
                                   Result.ABORTED)

    # -- lectura y verificación ------------------------------------------------
    @property
    def entries(self) -> list[Entry]:
        return _read_entries(self._con())

    def control_engagements(self, action: str, result: Result = Result.ABORTED) -> set[str]:
        row = self._con().execute(
            "SELECT 1 FROM audit WHERE action = ? AND phase = 'control' AND result = ? LIMIT 1",
            (action, result.value)).fetchone()
        return {self.engagement_id} if row else set()

    def killed_engagements(self) -> set[str]:
        return self.control_engagements(KILLSWITCH_ACTION)

    def verify_integrity(self) -> None:
        """Cadena íntegra y, dentro del proceso, sin registros perdidos al final.

        El ancla en memoria detecta un truncado del final o un archivo reemplazado mientras el
        proceso corre. Entre reinicios eso exige un ancla externa (ver design.md, riesgos).
        """
        # El ancla se lee ANTES que los registros: lo que otro hilo agregue después solo suma
        # filas. Al revés, una escritura concurrente parecía un truncado (carrera, ver 004).
        with self._anchor_lock:
            anchor = self._anchor
        entries = self.entries
        error = verify_chain(entries, genesis(self.engagement_id), engagement=self.engagement_id)
        if error is None and anchor is not None:
            n, last_hash = anchor
            if len(entries) < n or entries[n - 1]["hash"] != last_hash:
                error = f"faltan registros: se habían verificado {n} y el registro {n} no coincide"
        if error:
            raise AuditIntegrityError(error)
        if entries:
            with self._anchor_lock:             # el ancla solo avanza
                if self._anchor is None or len(entries) > self._anchor[0]:
                    self._anchor = (len(entries), entries[-1]["hash"])


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "verify":
        print("uso: python -m harness.audit verify <archivo.sqlite3>", file=sys.stderr)
        return 2
    error = verify_file(Path(argv[1]))
    if error:
        print(f"CADENA ROTA: {error}")
        return 1
    print("OK: cadena íntegra")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
