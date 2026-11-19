"""Snapshots offline de NVD y EPSS (change 005, D2 y D3).

Nada de este módulo abre conexiones. Los archivos de `data/feeds/` los genera una persona con
`tools/build_feeds.py` y se verifican contra `manifest.json` (SHA-256) al cargarlos.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "data" / "feeds"
ATTACK_MAP = ROOT / "data" / "attack_map.yaml"
NVD_FILE, EPSS_FILE, MANIFEST_FILE, ALIASES_FILE = (
    "nvd.json", "epss.csv", "manifest.json", "cpe_aliases.yaml")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CWE_RE = re.compile(r"^CWE-\d{1,5}$")
_VERSION_RE = re.compile(r"^\d+(\.\d+){0,5}$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_DISTROS = ("debian", "ubuntu", "red hat", "redhat", "centos", "rocky", "alma", "suse",
            "fedora", "alpine")
UNKNOWN_CWE = "unknown"


class FeedUnavailable(Exception):
    """El snapshot no se puede usar (falta, no coincide el hash o está mal formado)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# -- versiones y CPE -------------------------------------------------------------------
Version = tuple[int, ...]


def parse_version(raw: str | None) -> Version | None:
    """`2.4.25` → (2, 4, 25). Lo que no sea numérico con puntos no se interpreta (D3)."""
    if not raw or not _VERSION_RE.match(raw.strip()):
        return None
    return tuple(int(p) for p in raw.strip().split("."))


def _cmp(a: Version, b: Version) -> int:
    n = max(len(a), len(b))
    pa, pb = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (pa > pb) - (pa < pb)


@dataclass(frozen=True)
class CpeRange:
    """Un `cpeMatch` vulnerable de NVD: versión exacta o rango."""
    product: str                          # vendor:product, p. ej. apache:http_server
    exact: Version | None = None
    start_incl: Version | None = None
    start_excl: Version | None = None
    end_incl: Version | None = None
    end_excl: Version | None = None

    def matches(self, product: str, version: Version) -> bool:
        if product != self.product:
            return False
        if self.exact is not None:
            return _cmp(version, self.exact) == 0
        bounds = (self.start_incl, self.start_excl, self.end_incl, self.end_excl)
        if all(b is None for b in bounds):
            return False                  # "cualquier versión" no basta para afirmar nada
        return ((self.start_incl is None or _cmp(version, self.start_incl) >= 0)
                and (self.start_excl is None or _cmp(version, self.start_excl) > 0)
                and (self.end_incl is None or _cmp(version, self.end_incl) <= 0)
                and (self.end_excl is None or _cmp(version, self.end_excl) < 0))


@dataclass(frozen=True)
class CveRecord:
    id: str
    cwes: tuple[str, ...]                 # vacío = unknown
    cvss_score: float | None
    cvss_version: str | None              # "4.0" | "3.1" | None: nunca se convierte (D5)
    ranges: tuple[CpeRange, ...]


def _parse_cpe(criteria: str) -> tuple[str, str] | None:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3" or parts[2] != "a":
        return None
    return f"{parts[3]}:{parts[4]}".lower(), parts[5]


def _opt_version(raw: Any) -> Version | None:
    return parse_version(raw) if isinstance(raw, str) else None


def _cpe_ranges(configurations: Any) -> tuple[CpeRange, ...]:
    out: list[CpeRange] = []
    for conf in configurations or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if m.get("vulnerable") is not True or not isinstance(m.get("criteria"), str):
                    continue
                parsed = _parse_cpe(m["criteria"])
                if parsed is None:
                    continue
                product, ver = parsed
                exact = parse_version(ver) if ver not in ("*", "-") else None
                if ver not in ("*", "-") and exact is None:
                    continue              # versión exacta que no se entiende: no coincide
                out.append(CpeRange(product, exact,
                                    _opt_version(m.get("versionStartIncluding")),
                                    _opt_version(m.get("versionStartExcluding")),
                                    _opt_version(m.get("versionEndIncluding")),
                                    _opt_version(m.get("versionEndExcluding"))))
    return tuple(out)


def _cvss(metrics: Any) -> tuple[float | None, str | None]:
    for key, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1")):
        entries = (metrics or {}).get(key) or []
        ranked = sorted(entries, key=lambda e: e.get("type") != "Primary")
        for e in ranked:
            score = (e.get("cvssData") or {}).get("baseScore")
            if isinstance(score, int | float) and not isinstance(score, bool) \
                    and 0 <= score <= 10:
                return float(score), label
    return None, None


def _cwes(weaknesses: Any) -> tuple[str, ...]:
    found = {d.get("value") for w in weaknesses or [] for d in w.get("description", []) or []}
    return tuple(sorted(c for c in found if isinstance(c, str) and _CWE_RE.match(c)))


def parse_nvd(raw: str) -> dict[str, CveRecord]:
    data = json.loads(raw)
    records: dict[str, CveRecord] = {}
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not isinstance(cid, str) or not _CVE_RE.match(cid):
            continue
        score, version = _cvss(cve.get("metrics"))
        records[cid] = CveRecord(cid, _cwes(cve.get("weaknesses")), score, version,
                                 _cpe_ranges(cve.get("configurations")))
    return records


def parse_epss(raw: str) -> dict[str, float]:
    """CSV de FIRST: primera línea `#model_version:…,score_date:…`, luego `cve,epss,percentile`."""
    lines = [ln for ln in raw.splitlines() if ln and not ln.startswith("#")]
    scores: dict[str, float] = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        try:
            cid, score = row["cve"], float(row["epss"])
        except (KeyError, TypeError, ValueError):
            continue
        if _CVE_RE.match(cid or "") and 0.0 <= score <= 1.0:
            scores[cid] = score
    return scores


# -- carga verificada ------------------------------------------------------------------
@dataclass(frozen=True)
class Feeds:
    nvd: dict[str, CveRecord]
    epss: dict[str, float]
    aliases: dict[str, str]               # nombre en minúsculas → vendor:product
    retrieved_at: datetime
    stale: bool
    synthetic: bool

    def product_of(self, name: str) -> str | None:
        return self.aliases.get(name.strip().lower())

    def lookup(self, product: str, version: Version) -> list[CveRecord]:
        return sorted((r for r in self.nvd.values()
                       if any(rg.matches(product, version) for rg in r.ranges)),
                      key=lambda r: r.id)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_aliases(path: Path) -> dict[str, str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, str] = {}
    for product, names in (data.get("aliases") or {}).items():
        for name in names or []:
            out[str(name).strip().lower()] = str(product).lower()
    return out


def load_feeds(base: Path = FEEDS_DIR, *, max_age_days: int,
               now: datetime | None = None) -> Feeds:
    """Lanza FeedUnavailable si falta algo o si un hash no coincide con el manifiesto."""
    now = now or datetime.now(UTC)
    try:
        manifest = json.loads((base / MANIFEST_FILE).read_text(encoding="utf-8"))
        files = manifest["files"]
        for name in (NVD_FILE, EPSS_FILE, ALIASES_FILE):
            if _sha256(base / name) != files[name]["sha256"]:
                raise FeedUnavailable(f"hash_mismatch:{name}")
        retrieved = min(datetime.fromisoformat(files[n]["retrieved_at"])
                        for n in (NVD_FILE, EPSS_FILE))
        if retrieved.tzinfo is None:
            raise FeedUnavailable("manifest_invalid")
        nvd = parse_nvd((base / NVD_FILE).read_text(encoding="utf-8"))
        epss = parse_epss((base / EPSS_FILE).read_text(encoding="utf-8"))
        aliases = load_aliases(base / ALIASES_FILE)
    except FeedUnavailable:
        raise
    except FileNotFoundError as exc:
        raise FeedUnavailable("missing") from exc
    except (KeyError, TypeError, ValueError, AttributeError, yaml.YAMLError) as exc:
        raise FeedUnavailable("manifest_invalid") from exc
    return Feeds(nvd, epss, aliases, retrieved,
                 stale=now - retrieved > timedelta(days=max_age_days),
                 synthetic=bool(manifest.get("synthetic", False)))


def policy_max_age_days(policy: dict[str, Any] | None = None) -> int:
    """`limits.max_feed_age_days` de policy.yaml (D2). Un valor raro es un error, no un default."""
    from harness.policy_loader import load_policy

    value = (policy or load_policy())["limits"]["max_feed_age_days"]
    if type(value) is not int or value < 1:
        raise ValueError(f"limits.max_feed_age_days inválido: {value!r}")
    return value


def load_feeds_by_policy(base: Path = FEEDS_DIR, now: datetime | None = None) -> Feeds:
    return load_feeds(base, max_age_days=policy_max_age_days(), now=now)


def load_attack_map(path: Path = ATTACK_MAP) -> dict[str, str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in (data.get("cwe_to_attack") or {}).items()
            if _CWE_RE.match(str(k)) and _TECHNIQUE_RE.match(str(v))}


def split_tech(tech: str) -> tuple[str, str | None]:
    """`Apache httpd:2.4.25` → ("Apache httpd", "2.4.25"). Sin versión → (nombre, None)."""
    name, sep, version = tech.rpartition(":")
    return (name, version.strip()) if sep and name else (tech, None)


def is_distro_marker(techs: Iterable[str]) -> bool:
    """Un banner de distribución (Debian, Ubuntu…) avisa que puede haber backports (D4)."""
    return any(split_tech(t)[0].strip().lower() in _DISTROS
               or any(f"({d})" in t.lower() for d in _DISTROS) for t in techs)
