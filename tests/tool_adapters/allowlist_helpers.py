"""Copia de la allow-list con revisor, para tests (el manifiesto del repo espera revisión)."""
from __future__ import annotations

import shutil
from pathlib import Path

from harness.templates import ALLOWLIST, sha256_of


def approved_allowlist(dest: Path, reviewer: str = "Revisora del equipo") -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    for f in ALLOWLIST.glob("*.yaml"):
        shutil.copy(f, dest / f.name)
    lines = (ALLOWLIST / "MANIFEST.md").read_text(encoding="utf-8").splitlines()
    out = [ln.replace("| pendiente |", f"| {reviewer} |") for ln in lines]
    (dest / "MANIFEST.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    return dest


def rewrite_manifest_row(base: Path, template_id: str, **cells: str) -> None:
    cols = ("id", "archivo", "sha256", "origen", "detecta", "método", "autor", "revisor",
            "fecha")
    lines = (base / "MANIFEST.md").read_text(encoding="utf-8").splitlines()
    for i, ln in enumerate(lines):
        parts = [c.strip() for c in ln.strip().strip("|").split("|")]
        if parts and parts[0] == template_id:
            row = dict(zip(cols, parts, strict=True)) | cells
            lines[i] = "| " + " | ".join(row[c] for c in cols) + " |"
    (base / "MANIFEST.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def add_template(base: Path, name: str, body: str, *, register: bool,
                 reviewer: str = "Revisora del equipo") -> Path:
    path = base / f"{name}.yaml"
    path.write_text(body, encoding="utf-8")
    if register:
        with open(base / "MANIFEST.md", "a", encoding="utf-8") as fh:
            fh.write(f"| {name} | {name}.yaml | {sha256_of(path)} | propio | test | GET | "
                     f"Autor | {reviewer} | 2026-11-19 |\n")
    return path
