"""RoE (Rules of Engagement): parser y validación (change 003).

El RoE es la única fuente de autoridad del engagement. Se valida todo y se devuelven
todos los errores juntos, cada uno con su campo y motivo.

    python -m harness.roe hash <roe.yaml>   # calcula approval.roe_sha256
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from harness.contracts import Phase, normalize_target

_PROFILES = Path(__file__).resolve().parent / "profiles.yaml"
ENGAGEMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
MAX_WINDOW = timedelta(days=7)
REQUIRED = ("engagement_id", "scope", "window", "phases", "emergency_contacts", "approval")


class RoEError(ValueError):
    def __init__(self, code: str, errors: list[str]) -> None:
        self.code, self.errors = code, errors
        super().__init__(f"{code}: " + "; ".join(errors))


@dataclass(frozen=True)
class ReportDestination:
    """Destino del informe (007, D15): DefectDojo en la red `tools` del laboratorio."""
    host: str
    ip: str                       # una sola IP (el RoE la escribe como IP o como CIDR /32)
    port: int
    dd_engagement_id: int         # id del engagement en DefectDojo


@dataclass(frozen=True)
class RoE:
    engagement_id: str
    cidrs: tuple[str, ...]
    domains: tuple[str, ...]
    excluded: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    phases: frozenset[Phase]
    approver: str
    digest: str
    # change 005: criticidad opcional por host (1..5); un host sin entrada vale 3.
    criticality: tuple[tuple[str, int], ...] = ()
    # change 007: destinos del informe; vacío = entrega como archivo (modo offline).
    report_destinations: tuple[ReportDestination, ...] = ()
    # Fuente validada: el emisor vuelve a parsearla y no confía en los demás campos.
    source: dict[str, Any] = field(compare=False, repr=False, default_factory=dict)


def _canon(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _canon(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_canon(v) for v in value]
    return value


def roe_digest(data: dict[str, Any]) -> str:
    """SHA-256 del RoE canónico sin el bloque `approval`."""
    body = {k: v for k, v in data.items() if k != "approval"}
    return hashlib.sha256(
        json.dumps(_canon(body), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _destination_targets() -> tuple[list[ipaddress.IPv4Network | ipaddress.IPv6Network],
                                    list[str]]:
    targets = yaml.safe_load(_PROFILES.read_text(encoding="utf-8"))["targets"]
    return ([ipaddress.ip_network(c) for c in targets["report_destination_cidrs"]],
            [d.lower() for d in targets["report_destination_domains"]])


def _parse_destinations(raw: Any, errors: list[str]) -> tuple[ReportDestination, ...]:
    """`report_destinations` (007): solo hosts e IP de la red de herramientas de profiles.yaml.
    Por ahora un solo destino: la entrega registra un único `report.delivered`."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        errors.append("report_destinations: debe ser una lista")
        return ()
    if len(raw) > 1:
        errors.append("report_destinations: por ahora se admite un solo destino")
        return ()
    cidrs, domains = _destination_targets()
    out: list[ReportDestination] = []
    for i, item in enumerate(raw):
        where = f"report_destinations[{i}]"
        if not isinstance(item, dict) or set(item) != {"host", "ip", "port", "dd_engagement_id"}:
            errors.append(f"{where}: necesita host, ip, port y dd_engagement_id")
            continue
        host = normalize_target(str(item["host"]))
        if host is None or _is_ip_text(host) or not _in_domains(host, domains):
            errors.append(f"{where}: el destino {item['host']!r} está fuera de {domains}")
            continue
        try:
            net = ipaddress.ip_network(str(item["ip"]), strict=True)
        except ValueError:
            errors.append(f"{where}: IP inválida {item['ip']!r}")
            continue
        if net.num_addresses != 1 or not any(
                net.version == c.version and net.subnet_of(c)  # type: ignore[arg-type]
                for c in cidrs):
            errors.append(f"{where}: el destino {item['ip']} no es una IP de "
                          f"{[str(c) for c in cidrs]}")
            continue
        port, dd = item["port"], item["dd_engagement_id"]
        if type(port) is not int or not 1 <= port <= 65535:
            errors.append(f"{where}: puerto inválido {port!r}")
            continue
        if type(dd) is not int or dd < 1:
            errors.append(f"{where}: dd_engagement_id inválido {dd!r}")
            continue
        out.append(ReportDestination(host, str(net.network_address), port, dd))
    return tuple(out)


def _is_ip_text(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _lab_targets() -> tuple[list[ipaddress.IPv4Network | ipaddress.IPv6Network], list[str]]:
    targets = yaml.safe_load(_PROFILES.read_text(encoding="utf-8"))["targets"]
    return ([ipaddress.ip_network(c) for c in targets["lab_only_cidrs"]],
            [d.lower() for d in targets["lab_only_domains"]])


def _parse_instant(raw: Any, field: str, errors: list[str]) -> datetime | None:
    if isinstance(raw, str):
        try:
            raw = datetime.fromisoformat(raw)
        except ValueError:
            errors.append(f"{field}: fecha inválida {raw!r}")
            return None
    if not isinstance(raw, datetime):
        errors.append(f"{field}: debe ser fecha y hora ISO 8601 con zona horaria")
        return None
    if raw.tzinfo is None or raw.utcoffset() is None:
        errors.append(f"{field}: falta la zona horaria (se exige, p. ej. -03:00 o Z)")
        return None
    return raw.astimezone(UTC)


def _in_domains(host: str, allowed: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in allowed)


def parse_roe(source: str | dict[str, Any]) -> RoE:
    """Parsea y valida. Lanza RoEError con todos los errores encontrados.

    Un RoE malformado (tipos inesperados, fechas fuera de rango, tags YAML raros) se
    rechaza como `roe_invalid`: nunca sale una excepción cruda.
    """
    try:
        return _parse(source)
    except RoEError:
        raise
    except (TypeError, AttributeError, ValueError, OverflowError, KeyError,
            yaml.YAMLError) as exc:
        raise RoEError("roe_invalid", [f"RoE malformado: {type(exc).__name__}"]) from exc


def _as_dict(value: Any, field_name: str, errors: list[str]) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        errors.append(f"{field_name}: debe ser un mapa")
        return {}
    return value


def _parse(source: str | dict[str, Any]) -> RoE:
    data = yaml.safe_load(source) if isinstance(source, str) else copy.deepcopy(source)
    if not isinstance(data, dict):
        raise RoEError("roe_invalid", ["el RoE debe ser un mapa YAML"])
    errors: list[str] = [f"{f}: campo obligatorio" for f in REQUIRED if not data.get(f)]

    eng = data.get("engagement_id")
    if eng and not (isinstance(eng, str) and ENGAGEMENT_ID_RE.match(eng)):
        errors.append(f"engagement_id: formato inválido {eng!r}")

    lab_cidrs, lab_domains = _lab_targets()
    scope = _as_dict(data.get("scope"), "scope", errors)
    cidrs: list[str] = []
    for raw in scope.get("cidrs") or []:
        try:
            net = ipaddress.ip_network(str(raw), strict=True)
        except ValueError:
            errors.append(f"scope.cidrs: CIDR inválido {raw!r}")
            continue
        if not any(net.version == lab.version and net.subnet_of(lab)  # type: ignore[arg-type]
                   for lab in lab_cidrs):
            errors.append(f"scope.cidrs: {raw} fuera del laboratorio {[str(c) for c in lab_cidrs]}")
            continue
        cidrs.append(str(net))
    domains: list[str] = []
    for raw in scope.get("domains") or []:
        host = normalize_target(str(raw))
        if host is None or not _in_domains(host, lab_domains):
            errors.append(f"scope.domains: {raw} fuera del laboratorio {lab_domains}")
            continue
        domains.append(host)
    if data.get("scope") and not cidrs and not domains and not any("scope." in e for e in errors):
        errors.append("scope: el alcance está vacío")

    excl = _as_dict(data.get("exclusions"), "exclusions", errors)
    excluded: list[str] = []
    for raw in list(excl.get("hosts") or []) + list(excl.get("domains") or []):
        canon = normalize_target(str(raw))
        if canon is None:
            try:
                canon = str(ipaddress.ip_network(str(raw), strict=True))
            except ValueError:
                errors.append(f"exclusions: valor inválido {raw!r}")
                continue
        excluded.append(canon)
    if (cidrs or domains) and _excludes_everything(cidrs, domains, excluded):
        errors.append("exclusions: las exclusiones cubren todo el alcance")

    window = _as_dict(data.get("window"), "window", errors)
    start = _parse_instant(window.get("start"), "window.start", errors) if window else None
    end = _parse_instant(window.get("end"), "window.end", errors) if window else None
    if start and end:
        if start >= end:
            errors.append("window: el inicio debe ser anterior al fin")
        elif end - start > MAX_WINDOW:
            errors.append(f"window: dura más de {MAX_WINDOW.days} días")

    phases: set[Phase] = set()
    for raw in data.get("phases") or []:
        try:
            phases.add(Phase(raw))
        except ValueError:
            errors.append(f"phases: fase desconocida {raw!r}")

    contacts = data.get("emergency_contacts") or []
    if contacts and not all(isinstance(c, dict) and c.get("name") and c.get("channel")
                            for c in contacts):
        errors.append("emergency_contacts: cada contacto necesita name y channel")

    criticality = _parse_criticality(data.get("criticality"), cidrs, domains, errors)
    destinations = _parse_destinations(data.get("report_destinations"), errors)

    approval = _as_dict(data.get("approval"), "approval", errors)
    if approval and not approval.get("approver"):
        errors.append("approval.approver: campo obligatorio")

    if errors:
        raise RoEError("roe_invalid", errors)

    digest = roe_digest(data)
    if approval.get("roe_sha256") != digest:
        raise RoEError("roe_tampered",
                       ["approval.roe_sha256: el contenido cambió después de aprobado"])

    assert start is not None and end is not None
    return RoE(engagement_id=str(eng), cidrs=tuple(cidrs), domains=tuple(domains),
               excluded=tuple(excluded), window_start=start, window_end=end,
               phases=frozenset(phases), approver=str(approval["approver"]), digest=digest,
               criticality=criticality, report_destinations=destinations, source=data)


DEFAULT_CRITICALITY = 3


def criticality_of(roe: RoE, host: str) -> tuple[int, bool]:
    """(criticidad, es_por_defecto) del host según el RoE (change 005, D6)."""
    value = dict(roe.criticality).get(host)
    return (DEFAULT_CRITICALITY, True) if value is None else (value, False)


def _parse_criticality(raw: Any, cidrs: list[str], domains: list[str],
                       errors: list[str]) -> tuple[tuple[str, int], ...]:
    entries = _as_dict(raw, "criticality", errors)
    out: list[tuple[str, int]] = []
    for key, value in entries.items():
        host = normalize_target(str(key))
        if host is None:
            errors.append(f"criticality: host inválido {key!r}")
            continue
        try:
            ip = ipaddress.ip_address(host)
            inside = any(ip in ipaddress.ip_network(c) for c in cidrs)
        except ValueError:
            inside = _in_domains(host, domains)
        if not inside:
            errors.append(f"criticality: {key} está fuera del alcance")
            continue
        if type(value) is not int or not 1 <= value <= 5:
            errors.append(f"criticality.{key}: debe ser un entero de 1 a 5")
            continue
        out.append((host, value))
    return tuple(sorted(out))


def _excludes_everything(cidrs: list[str], domains: list[str], excluded: list[str]) -> bool:
    """True si las exclusiones (también por unión, p. ej. dos /25) cubren todo el alcance."""
    nets = []
    for e in excluded:
        try:
            nets.append(ipaddress.ip_network(e))
        except ValueError:
            continue
    for c in cidrs:
        net = ipaddress.ip_network(c)
        inside = [n for n in nets if n.version == net.version and n.overlaps(net)]
        clipped: list[Any] = [n if n.subnet_of(net) else net  # type: ignore[arg-type]
                              for n in inside]
        covered: int = sum(n.num_addresses for n in ipaddress.collapse_addresses(clipped))
        if covered < net.num_addresses:
            return False
    return all(_in_domains(d, excluded) for d in domains)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "hash":
        print("uso: python -m harness.roe hash <roe.yaml>", file=sys.stderr)
        return 2
    print(roe_digest(yaml.safe_load(Path(argv[1]).read_text(encoding="utf-8"))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
