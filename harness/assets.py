"""AssetGraph del loop A: SQLite append-only, un archivo por engagement (change 004, D8).

La versión del grafo es el número de iteración. Un activo ya visto no se vuelve a insertar
(id único = deduplicación), y "activos nuevos" de la iteración i son los insertados en ella.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from harness.contracts import _is_ip, normalize_target
from harness.schemas import Asset, SchemaError

ENGAGEMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
ASSET_TYPES = ("domain", "ip", "http_service")
_VERSIONED = re.compile(r":\s*v?\d")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL CHECK (type IN ('domain','ip','http_service')),
  address     TEXT NOT NULL,
  source_tool TEXT NOT NULL CHECK (source_tool <> ''),
  iteration   INTEGER NOT NULL CHECK (iteration >= 0),
  in_scope    INTEGER NOT NULL CHECK (in_scope IN (0, 1)),
  reason      TEXT
);
CREATE TABLE IF NOT EXISTS asset_tech (
  asset_id    TEXT NOT NULL REFERENCES assets(id),
  tech        TEXT NOT NULL,
  source_tool TEXT NOT NULL CHECK (source_tool <> ''),
  iteration   INTEGER NOT NULL,
  UNIQUE (asset_id, tech)
);
CREATE TABLE IF NOT EXISTS loop_events (
  kind      TEXT NOT NULL CHECK (kind IN ('iteration_done','stop','tool_disabled')),
  value     TEXT NOT NULL,
  iteration INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS loop_events_no_update BEFORE UPDATE ON loop_events
BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS loop_events_no_delete BEFORE DELETE ON loop_events
BEGIN SELECT RAISE(ABORT, 'append-only: DELETE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS assets_no_update BEFORE UPDATE ON assets
BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS assets_no_delete BEFORE DELETE ON assets
BEGIN SELECT RAISE(ABORT, 'append-only: DELETE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS asset_tech_no_update BEFORE UPDATE ON asset_tech
BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS asset_tech_no_delete BEFORE DELETE ON asset_tech
BEGIN SELECT RAISE(ABORT, 'append-only: DELETE prohibido'); END;
"""


def canonical_address(kind: str, address: str) -> str:
    """Dirección normalizada según el tipo, o SchemaError."""
    if kind not in ASSET_TYPES:
        raise SchemaError(f"tipo de activo desconocido: {kind!r}")
    if kind == "http_service":
        parts = urlsplit(address)
        host = normalize_target(parts.hostname or "")
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise SchemaError(f"puerto inválido: {address!r}") from exc
        if parts.scheme not in ("http", "https") or host is None:
            raise SchemaError(f"servicio HTTP inválido: {address!r}")
        shown = f"[{host}]" if _is_ip(host) and ipaddress.ip_address(host).version == 6 else host
        return f"{parts.scheme}://{shown}:{port}"
    canon = normalize_target(address)
    if canon is None or (kind == "ip") != _is_ip(canon):
        raise SchemaError(f"{kind} inválido: {address!r}")
    return canon


def asset_id(kind: str, address: str) -> str:
    return hashlib.sha256(f"{kind}:{canonical_address(kind, address)}".encode()).hexdigest()


def has_version(tech: str) -> bool:
    return bool(_VERSIONED.search(tech))


class AssetGraph:
    def __init__(self, engagement_id: str, path: Path) -> None:
        self.engagement_id, self.path = engagement_id, path
        self._con = sqlite3.connect(path, timeout=30, isolation_level=None)

    @classmethod
    def open(cls, engagement_id: str, base_dir: Path | str = "state") -> AssetGraph:
        if not ENGAGEMENT_ID_RE.match(engagement_id):
            raise ValueError(f"engagement_id inválido: {engagement_id!r}")
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        graph = cls(engagement_id, base / f"{engagement_id}.assets.sqlite3")
        graph._con.executescript(_SCHEMA)
        return graph

    def close(self) -> None:
        self._con.close()

    def add(self, kind: str, address: str, *, source_tool: str, iteration: int,
            in_scope: bool = True, reason: str | None = None) -> Asset | None:
        """Agrega el activo. Devuelve None si ya estaba (no es nuevo)."""
        if not source_tool:
            raise SchemaError("Asset requiere source_tool")
        canon = canonical_address(kind, address)
        asset = Asset(id=asset_id(kind, canon), type=kind, address=canon,
                      source_tool=source_tool, iteration=iteration, in_scope=in_scope,
                      reason=reason)
        cur = self._con.execute(
            "INSERT OR IGNORE INTO assets (id, type, address, source_tool, iteration, in_scope,"
            " reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (asset.id, kind, canon, source_tool, iteration, int(in_scope), reason))
        return asset if cur.rowcount == 1 else None

    def add_tech(self, asset_id_: str, tech: str, *, source_tool: str, iteration: int) -> bool:
        if not tech or not source_tool:
            raise SchemaError("tecnología y source_tool son obligatorios")
        cur = self._con.execute(
            "INSERT OR IGNORE INTO asset_tech (asset_id, tech, source_tool, iteration)"
            " VALUES (?, ?, ?, ?)", (asset_id_, tech, source_tool, iteration))
        return cur.rowcount == 1

    def assets(self, in_scope: bool | None = None) -> list[Asset]:
        techs: dict[str, list[str]] = {}
        for aid, tech in self._con.execute(
                "SELECT asset_id, tech FROM asset_tech ORDER BY rowid"):
            techs.setdefault(aid, []).append(tech)
        rows = self._con.execute(
            "SELECT id, type, address, source_tool, iteration, in_scope, reason FROM assets"
            " ORDER BY iteration, rowid").fetchall()
        found = [Asset(id=r[0], type=r[1], address=r[2], source_tool=r[3],
                       technologies=tuple(techs.get(r[0], ())), iteration=r[4],
                       in_scope=bool(r[5]), reason=r[6]) for r in rows]
        return [a for a in found if in_scope is None or a.in_scope is in_scope]

    def new_in(self, iteration: int) -> list[Asset]:
        return [a for a in self.assets() if a.iteration == iteration]

    def last_iteration(self) -> int:
        row = self._con.execute("SELECT MAX(iteration) FROM assets").fetchone()
        return -1 if row[0] is None else int(row[0])

    # -- estado del loop (persistido: vale entre corridas) ------------------------------
    def _event(self, kind: str, value: str, iteration: int) -> None:
        self._con.execute("INSERT INTO loop_events (kind, value, iteration) VALUES (?, ?, ?)",
                          (kind, value, iteration))

    def mark_done(self, iteration: int) -> None:
        self._event("iteration_done", str(iteration), iteration)

    def last_done(self) -> int:
        row = self._con.execute(
            "SELECT MAX(iteration) FROM loop_events WHERE kind = 'iteration_done'").fetchone()
        return 0 if row[0] is None else int(row[0])

    def mark_stop(self, reason: str, iteration: int) -> None:
        self._event("stop", reason, iteration)

    def stop_reason(self) -> str | None:
        row = self._con.execute(
            "SELECT value FROM loop_events WHERE kind = 'stop' ORDER BY rowid LIMIT 1").fetchone()
        return None if row is None else str(row[0])

    def mark_disabled(self, tool: str, iteration: int) -> None:
        self._event("tool_disabled", tool, iteration)

    def disabled_tools(self) -> set[str]:
        return {str(r[0]) for r in self._con.execute(
            "SELECT value FROM loop_events WHERE kind = 'tool_disabled'")}

    def handoff(self) -> list[Asset]:
        """Activos en alcance con al menos una tecnología con versión (design.md D11)."""
        return [a for a in self.assets(in_scope=True)
                if any(has_version(t) for t in a.technologies)]
