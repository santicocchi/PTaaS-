"""Allow-list de templates de nuclei: manifiesto con hash y control estático (change 005, D9)."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "templates" / "allowlist"
_COLUMNS = ("id", "archivo", "sha256", "origen", "detecta", "método", "autor", "revisor", "fecha")
_FILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}\.yaml$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
PENDING = "pendiente"
ALLOWED_METHODS = {"GET", "HEAD"}
FORBIDDEN_KEYS = {"payloads", "fuzzing", "attack", "code", "headless", "dns", "network", "tcp",
                  "ssl", "websocket", "whois", "javascript", "file", "workflows", "flow",
                  "self-contained", "unsafe", "raw", "pipeline", "race", "threads"}


@dataclass(frozen=True)
class ManifestEntry:
    id: str
    file: str
    sha256: str
    author: str
    reviewer: str

    @property
    def approved(self) -> bool:
        return bool(self.reviewer) and self.reviewer.lower() != PENDING \
            and self.reviewer.strip().lower() != self.author.strip().lower()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(base: Path = ALLOWLIST) -> list[ManifestEntry]:
    """Lee la tabla de MANIFEST.md. Una fila mal formada se ignora (no se ejecuta)."""
    entries = []
    for line in (base / "MANIFEST.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != len(_COLUMNS) or cells[0] in ("id", "") or set(cells[0]) <= {"-"}:
            continue
        row = dict(zip(_COLUMNS, cells, strict=True))
        if not _FILE_RE.match(row["archivo"]) or not _SHA_RE.match(row["sha256"]):
            continue
        entries.append(ManifestEntry(row["id"], row["archivo"], row["sha256"], row["autor"],
                                     row["revisor"]))
    return entries


def runnable(base: Path = ALLOWLIST) -> tuple[list[Path], list[str]]:
    """(templates que pueden correr, motivos de los que no). Se llama antes de cada corrida."""
    ok, skipped = [], []
    for e in load_manifest(base):
        path = base / e.file
        if not path.is_file():
            skipped.append(f"{e.id}: falta el archivo")
        elif sha256_of(path) != e.sha256:
            skipped.append(f"{e.id}: el hash no coincide con el manifiesto")
        elif not e.approved:
            skipped.append(f"{e.id}: sin revisor distinto del autor")
        elif problems(path):
            skipped.append(f"{e.id}: no pasa el control estático")
        else:
            ok.append(path)
    return ok, skipped


def _walk_keys(node: Any) -> set[str]:
    if isinstance(node, dict):
        return set(map(str, node)) | {k for v in node.values() for k in _walk_keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _walk_keys(v)}
    return set()


def problems(path: Path, exclude_tags: set[str] | None = None) -> list[str]:
    """Control estático de un template. Lista vacía = cumple."""
    from harness.adapters.common import load_profiles

    excluded = exclude_tags if exclude_tags is not None else set(
        load_profiles()["nuclei"]["exclude_tags"])
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return [f"no se puede leer: {type(exc).__name__}"]
    if not isinstance(data, dict):
        return ["no es un mapa YAML"]
    found: list[str] = []
    if data.get("id") != path.stem:
        found.append("el id no coincide con el nombre del archivo")
    protocols = set(data) - {"id", "info", "http", "variables"}
    if protocols:
        found.append(f"claves no permitidas: {sorted(protocols)}")
    bad_keys = _walk_keys(data.get("http")) & FORBIDDEN_KEYS
    if bad_keys:
        found.append(f"campos prohibidos: {sorted(bad_keys)}")
    requests = data.get("http")
    if not isinstance(requests, list) or not requests:
        found.append("sin bloque http")
        requests = []
    for req in requests:
        if not isinstance(req, dict):
            found.append("request inválido")
            continue
        if str(req.get("method", "GET")).upper() not in ALLOWED_METHODS:
            found.append(f"método no permitido: {req.get('method')}")
        if req.get("redirects") not in (None, False) or req.get("host-redirects"):
            found.append("redirecciones activadas")
        if "body" in req:
            found.append("request con cuerpo")
        headers = req.get("headers")
        if isinstance(headers, dict) and any(str(k).strip().lower() == "host" for k in headers):
            found.append("fija su propio Host")      # el Host lo fija el adaptador (D7)
        for p in req.get("path") or []:
            if not str(p).startswith("{{BaseURL}}/"):
                found.append(f"ruta fuera del objetivo: {p}")
    raw_info = data.get("info")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    raw_tags = info.get("tags", "")
    items = raw_tags if isinstance(raw_tags, list) else str(raw_tags).split(",")
    tags = {str(t).strip().lower() for t in items if str(t).strip()}   # nuclei acepta lista
    if tags & excluded:
        found.append(f"tags excluidas: {sorted(tags & excluded)}")
    if "interactsh" in text.lower() or "oast" in tags:
        found.append("usa OAST/interactsh")
    return found
