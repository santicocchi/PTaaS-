"""Demo del Checkpoint 1: RoE → scope token → acciones permitidas y bloqueadas → bitácora.

    python -m demo.checkpoint1             # simulación: no sale ni un paquete de la máquina
    python -m demo.checkpoint1 --lab       # laboratorio real, desde el contenedor `runner`
    python -m demo.checkpoint1 --pausa     # espera Enter entre pasos (para presentar en vivo)

Todo pasa por `Harness.invoke`, igual que en producción. Lo único que cambia entre los dos
modos es qué hay detrás de los adaptadores y del DNS:

- simulación: el adaptador nmap arma el comando y NO lo ejecuta; el DNS es una tabla fija con
  los hosts del laboratorio; la verificación del catálogo evalúa una respuesta de ejemplo.
- --lab: nmap corre de verdad contra dvwa.lab.test y la verificación hace un GET al DVWA, todo
  dentro de la red `internal` del docker-compose (sin salida a internet).

El único objetivo que se toca es el laboratorio propio. Los intentos fuera de alcance usan
203.0.113.7 (rango TEST-NET-3, reservado para documentación) y el Harness los corta antes
de llegar a cualquier herramienta.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import ipaddress
import os
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from harness.adapters.nmap_adapter import NmapServiceScan
from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import (
    Action,
    Guard,
    Harness,
    KillSwitch,
    KillSwitchEngaged,
    Phase,
    Result,
    ScopeToken,
    ScopeViolation,
    system_resolver,
)
from harness.poc.catalog import ResponseRecord, load_catalog, run_parametrized
from harness.policy_loader import phase_allowlist
from harness.roe import RoE, RoEError, parse_roe, roe_digest
from harness.tokens import TokenIssuer

ROOT = Path(__file__).resolve().parent
ROE_TEMPLATE = ROOT / "roe-lab.yaml"
OUTSIDER = "203.0.113.7"          # TEST-NET-3: nadie la usa, y además nunca se le envía nada
LAB_DNS = {"dvwa.lab.test": ["10.99.0.10"], "juiceshop.lab.test": ["10.99.0.11"]}

# ---- presentación --------------------------------------------------------------------------

_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def ok(text: str) -> str:
    return _c("32", text)


def bad(text: str) -> str:
    return _c("31", text)


def warn(text: str) -> str:
    return _c("33", text)


def dim(text: str) -> str:
    return _c("2", text)


class Show:
    def __init__(self, pause: bool) -> None:
        self.pause, self.n = pause, 0

    def step(self, title: str, why: str) -> None:
        if self.pause and self.n:
            input(dim("\n   [Enter para seguir] "))
        self.n += 1
        print(f"\n{_c('1;36', f'── Paso {self.n}. {title}')}")
        print(dim(f"   {why}"))

    @staticmethod
    def line(text: str = "") -> None:
        print(f"   {text}")


# ---- piezas que cambian entre simulación y laboratorio --------------------------------------

def simulated_dns(host: str) -> list[str]:
    return LAB_DNS.get(host, [])


def poisoned_dns(host: str) -> list[str]:
    """DNS envenenado: el nombre autorizado ahora apunta afuera del laboratorio."""
    return [OUTSIDER]


class CommandRecorder:
    """Runner del modo simulación: guarda el comando que se ejecutaría y no ejecuta nada."""

    def __init__(self) -> None:
        self.last: list[str] = []

    def __call__(self, argv: list[str], timeout_s: int) -> str:
        self.last = list(argv)
        return ""


def lab_get(poc_id: str, params: dict[str, str], address: str) -> ResponseRecord:
    """GET dentro del laboratorio: sin proxy, sin seguir redirecciones (004, A5) y a la IP que
    validó el Harness, con el nombre en `Host` (004, DNS rebinding)."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None

    path = params["path"]
    # La ruta tiene que empezar con "/": sin eso, "@otro.host/x" cambiaría el destino.
    if not path.startswith("/") or path.startswith("//") or any(c <= " " for c in path):
        raise ValueError(f"ruta inválida: {path!r}")
    ip = ipaddress.ip_address(address)
    netloc = f"[{ip}]" if ip.version == 6 else str(ip)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    host = urllib.parse.urlsplit(params["base_url"]).hostname or ""
    request = urllib.request.Request(f"http://{netloc}{path}", headers={"Host": host})
    try:
        with opener.open(request, timeout=10) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
            return ResponseRecord(resp.status, dict(resp.headers.items()), body)
    except urllib.error.HTTPError as err:          # 3xx/4xx/5xx también son respuesta
        return ResponseRecord(err.code, dict(err.headers.items()), "")


def simulated_get(poc_id: str, params: dict[str, str], address: str) -> ResponseRecord:
    return ResponseRecord(200, {"Server": "Apache (respuesta de ejemplo)"}, "<html>…</html>")


class CatalogPoc:
    """Adaptador de la demo para `poc_catalog.run_parametrized` (el real llega con 006).

    Solo ejecuta verificaciones inertes del catálogo versionado, con la URL armada a partir
    del host que ya validó el Harness. Si este método corre es porque el gate humano ya pasó.
    """
    name = "poc_catalog.run_parametrized"
    allowed_phases = (Phase.VALIDATE,)
    destructive = False

    def __init__(self, sender: Callable[[str, dict[str, str], str], ResponseRecord],
                 poc_id: str = "POC-HDR-001", path: str = "/login.php") -> None:
        self.sender, self.poc_id, self.path = sender, poc_id, path

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        evidence = run_parametrized(load_catalog(), self.poc_id,
                                    {"base_url": f"http://{target}", "path": self.path},
                                    approved=True,
                                    sender=lambda pid, prm: self.sender(pid, prm, addresses[0]))
        return {"tool": "poc_catalog", "target": target, "poc_id": evidence.poc_id,
                "status": evidence.status, "detail": evidence.detail}


def open_ports(xml_text: str) -> list[str]:
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)      # salida de nmap contra nuestro propio laboratorio
    found = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            svc = port.find("service")
            name = "" if svc is None else " ".join(
                filter(None, [svc.get("name"), svc.get("product"), svc.get("version")]))
            found.append(f"{port.get('portid')}/{port.get('protocol')} {name}".strip())
    return found


# ---- RoE -----------------------------------------------------------------------------------

def prepare_roe(engagement_id: str, now: datetime) -> dict[str, Any]:
    """Completa el RoE de la demo y lo "aprueba" (calcula el hash como haría el reviewer)."""
    data: dict[str, Any] = yaml.safe_load(ROE_TEMPLATE.read_text(encoding="utf-8"))
    data["engagement_id"] = engagement_id
    data["window"] = {"start": (now - timedelta(minutes=5)).isoformat(timespec="seconds"),
                      "end": (now + timedelta(hours=8)).isoformat(timespec="seconds")}
    data["approval"]["roe_sha256"] = roe_digest(data)
    return data


# ---- la demo -------------------------------------------------------------------------------

def attempt(harness: Harness, agent: str, action: Action, target: str,
            token: ScopeToken) -> dict[str, Any] | None:
    label = f"{agent} → {action.name} sobre {target}"
    try:
        out = harness.invoke(agent, action, target, token)
    except ScopeViolation as exc:
        reason = str(exc).rsplit(": ", 1)[-1]
        Show.line(f"{bad('BLOQUEADA')}  {label}  {dim('motivo: ' + reason)}")
        return None
    except KillSwitchEngaged:
        Show.line(f"{bad('ABORTADA')}   {label}  {dim('kill switch activo')}")
        return None
    if out.get("status") == Result.PENDING_HITL.value:
        Show.line(f"{warn('EN ESPERA')}  {label}  {dim('falta aprobación humana (HITL)')}")
        return None
    Show.line(f"{ok('PERMITIDA')}  {label}")
    return out


def run(lab: bool, pause: bool, out_dir: Path) -> int:
    show = Show(pause)
    now = datetime.now(UTC)
    engagement_id = "demo-cp1-" + now.strftime("%Y%m%d-%H%M%S")
    resolver = system_resolver if lab else simulated_dns
    recorder = CommandRecorder()
    nmap = NmapServiceScan() if lab else NmapServiceScan(runner=recorder)
    poc = CatalogPoc(lab_get if lab else simulated_get)
    mode = "LABORATORIO REAL (red aislada)" if lab else "SIMULACIÓN (no se envía tráfico)"
    print(_c("1", f"PTaaS · Demo Checkpoint 1 · engagement {engagement_id} · {mode}"))

    # 1. RoE mal armado ----------------------------------------------------------------------
    show.step("Un RoE mal armado no arranca nada",
              "El RoE es la única fuente de autoridad. Se validan todos los campos y se "
              "devuelven todos los errores juntos.")
    roe_data = prepare_roe(engagement_id, now)
    broken = copy.deepcopy(roe_data)
    broken["scope"] = {"cidrs": ["0.0.0.0/0"], "domains": ["example.com"]}
    broken["window"]["start"] = "2026-11-19T10:00:00"            # sin zona horaria
    broken["emergency_contacts"] = []
    try:
        parse_roe(broken)
    except RoEError as exc:
        Show.line(f"{bad(exc.code)} ({len(exc.errors)} errores):")
        for err in exc.errors:
            Show.line(f"  · {err}")

    # 2. RoE aprobado y RoE adulterado -------------------------------------------------------
    show.step("El RoE aprobado, y qué pasa si alguien lo toca después",
              "El reviewer aprueba firmando el hash SHA-256 del contenido "
              "(python -m harness.roe hash). Cambiar una coma invalida la aprobación.")
    roe: RoE = parse_roe(roe_data)
    Show.line(f"{ok('RoE válido')}  aprobado por {roe.approver}  sha256={roe.digest[:16]}…")
    Show.line(f"alcance: {', '.join(roe.cidrs + roe.domains)}")
    Show.line(f"excluido: {', '.join(roe.excluded)}  ·  fases: "
              f"{', '.join(sorted(p.value for p in roe.phases))}")
    Show.line(f"ventana: {roe.window_start:%H:%M} a {roe.window_end:%H:%M} UTC")
    tampered = copy.deepcopy(roe_data)
    tampered["exclusions"]["hosts"] = []          # alguien saca la exclusión sin re-aprobar
    try:
        parse_roe(tampered)
    except RoEError as exc:
        Show.line(f"Se borra la exclusión sin re-aprobar → {bad(exc.code)}: {exc.errors[0]}")

    # 3. Tokens ------------------------------------------------------------------------------
    show.step("Scope tokens: uno por fase, firmados y con vencimiento",
              "Solo el emisor crea tokens, a partir del RoE validado. Llevan HMAC-SHA256 y "
              "duran lo que dice policy.yaml (nunca más que la ventana).")
    audit = SqliteAuditLog.open(engagement_id, out_dir)
    issuer = TokenIssuer(audit)
    recon = issuer.issue(roe, Phase.RECON)
    ttl = (recon.window_end - recon.window_start) / 60
    Show.line(f"{ok('token recon emitido')}  vence en {ttl:.0f} min  mac={recon.mac[:16]}…")
    try:
        issuer.issue(roe, Phase.ANALYZE)
    except ScopeViolation as exc:
        Show.line(f"Pedido de token analyze → {bad('rechazado')}: {str(exc).split(': ')[-1]}"
                  f"  {dim('(el RoE solo habilita recon y validate)')}")

    guard = Guard(phase_allowlist())
    tools: dict[str, Any] = {nmap.name: nmap, poc.name: poc}
    harness = Harness(guard, audit, tools, KillSwitch(), issuer, resolver=resolver)
    scan = Action("nmap.service_scan", Phase.RECON)

    # 4. Acción permitida --------------------------------------------------------------------
    show.step("Acción permitida: recon sobre un host del alcance",
              "Pasa token, guard, adaptador y DNS (el nombre resuelve dentro del alcance). "
              "La decisión queda en bitácora ANTES de ejecutar (write-ahead).")
    result = attempt(harness, "recon-agent", scan, "dvwa.lab.test", recon)
    if result is not None and lab:
        ports = open_ports(result.get("raw", ""))
        Show.line(f"puertos abiertos: {', '.join(ports) or 'ninguno reportado'}")
    elif result is not None:
        Show.line(dim("comando que se ejecutaría (sin shell): ") + " ".join(recorder.last))

    # 5. Bloqueos del guard ------------------------------------------------------------------
    show.step("Acciones bloqueadas por el Scope Guard (determinista, sin LLM)",
              "Cada intento bloqueado también queda en bitácora, con su motivo.")
    attempt(harness, "recon-agent", scan, OUTSIDER, recon)
    attempt(harness, "recon-agent", scan, "juiceshop.lab.test", recon)
    attempt(harness, "recon-agent", Action("zap.baseline_scan", Phase.ANALYZE),
            "dvwa.lab.test", recon)
    attempt(harness, "recon-agent", Action("sqlmap.dump", Phase.RECON), "dvwa.lab.test", recon)

    # 6. Token falsificado -------------------------------------------------------------------
    show.step("Un agente se agranda el token",
              "Copia el token y le pone 0.0.0.0/0 como alcance. La firma ya no coincide.")
    forged = dataclasses.replace(recon, allowed_cidrs=("0.0.0.0/0",))
    attempt(harness, "recon-agent", scan, OUTSIDER, forged)

    # 7. DNS envenenado (red team A4) --------------------------------------------------------
    show.step("DNS envenenado (bypass A4 del red team, ya corregido)",
              "El nombre está en el RoE, pero ahora resuelve a una IP de afuera. Antes del "
              "fix pasaba; ahora el Harness valida la IP resuelta.")
    poisoned = Harness(guard, audit, tools, harness.killswitch, issuer, resolver=poisoned_dns)
    Show.line(dim(f"dvwa.lab.test → {OUTSIDER} (simulado)"))
    attempt(poisoned, "recon-agent", scan, "dvwa.lab.test", recon)

    # 8. Gate humano (red team R13) ----------------------------------------------------------
    show.step("Validación con gate humano (bypass R13 del red team, ya corregido)",
              "El agente arma la acción diciendo que no necesita aprobación. Lo decide la "
              "política, no el agente: validate siempre espera al reviewer.")
    validate = issuer.issue(roe, Phase.VALIDATE)
    poc_action = Action("poc_catalog.run_parametrized", Phase.VALIDATE,
                        requires_human_approval=False)
    attempt(harness, "validation-agent", poc_action, "dvwa.lab.test", validate)
    guard.approve(poc_action.name, "dvwa.lab.test", engagement_id=engagement_id,
                  phase=Phase.VALIDATE)
    Show.line(dim("el reviewer aprueba POC-HDR-001 sobre dvwa.lab.test"))
    evidence = attempt(harness, "validation-agent", poc_action, "dvwa.lab.test", validate)
    if evidence is not None:
        sample = "" if lab else dim("  (respuesta de ejemplo)")
        Show.line(f"{evidence['poc_id']}: {evidence['status']} · {evidence['detail']}{sample}")

    # 9. Kill switch -------------------------------------------------------------------------
    show.step("Kill switch, y sigue activo después de reiniciar",
              "Se registra en bitácora antes de activarse en memoria. Al arrancar, el Harness "
              "lo lee de la bitácora: reiniciar no lo apaga.")
    harness.kill(engagement_id, "operator")
    attempt(harness, "recon-agent", scan, "dvwa.lab.test", recon)
    audit.close()
    audit = SqliteAuditLog.open(engagement_id, out_dir)
    restarted = Harness(Guard(phase_allowlist()), audit, tools, KillSwitch(), issuer,
                        resolver=resolver)
    Show.line(dim("proceso reiniciado (bitácora reabierta, kill switch en memoria vacío)"))
    attempt(restarted, "recon-agent", scan, "dvwa.lab.test", recon)

    # 10. Bitácora ---------------------------------------------------------------------------
    show.step("La bitácora: append-only y con hash encadenado",
              "Todo lo anterior quedó registrado, incluidos los bloqueos. Cada registro "
              "incluye el hash del anterior.")
    entries = audit.entries
    Show.line(dim(f"{'seq':>3}  {'agente':<16} {'acción':<29} {'objetivo':<19} "
                  f"{'resultado':<12} motivo"))
    for e in entries:
        color = {"OK": ok, "BLOCKED": bad, "ABORTED": bad, "PENDING_HITL": warn}[e["result"]]
        target = e["target"] if len(e["target"]) <= 19 else e["target"][:18] + "…"
        shown = color(f"{e['result']:<12}")
        Show.line(f"{e['seq']:>3}  {e['agent']:<16} {e['action']:<29} {target:<19} "
                  f"{shown} {e.get('reason') or ''}")
    path = audit.path
    audit.close()
    Show.line()
    Show.line(f"python -m harness.audit verify {path}")
    error = verify_file(path)
    Show.line(ok("OK: cadena íntegra") if error is None else bad(f"CADENA ROTA: {error}"))

    con = sqlite3.connect(path)
    try:
        con.execute("UPDATE audit SET result = 'OK' WHERE result = 'BLOCKED'")
    except sqlite3.DatabaseError as exc:
        Show.line(f"Intento de borrar los bloqueos con UPDATE → {bad('rechazado')}: {exc}")
    finally:
        con.close()

    copy_dir = out_dir / "manipulada"
    copy_dir.mkdir(parents=True, exist_ok=True)
    forged_path = copy_dir / path.name
    forged_path.unlink(missing_ok=True)
    with sqlite3.connect(path) as src, sqlite3.connect(forged_path) as dst:
        src.backup(dst)
    con = sqlite3.connect(forged_path)
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("UPDATE audit SET result = 'OK', reason = NULL WHERE reason = 'out_of_scope'")
    con.commit()
    con.close()
    Show.line("Copia en la que un atacante borró el trigger y 'limpió' el intento fuera de "
              "alcance:")
    error = verify_file(forged_path)
    Show.line(ok("OK: cadena íntegra") if error is None else bad(f"CADENA ROTA: {error}"))

    blocked = sum(e["result"] == "BLOCKED" for e in entries)
    allowed = sum(e["result"] == "OK" and e["phase"] != "control" for e in entries)
    print(_c("1", f"\nResumen: {allowed} acciones ejecutadas, {blocked} bloqueadas, "
                  f"{len(entries)} registros en {path}"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--lab", action="store_true",
                        help="ejecutar de verdad contra el laboratorio (desde el runner)")
    parser.add_argument("--pausa", action="store_true", help="esperar Enter entre pasos")
    parser.add_argument("--out", type=Path, default=ROOT / "out",
                        help="carpeta de la bitácora (por defecto demo/out)")
    args = parser.parse_args(argv)
    if args.lab and not _lab_reachable():
        print("No se resuelve dvwa.lab.test: --lab se corre dentro del contenedor runner:\n"
              "  docker compose -f lab/docker-compose.yml up -d --build\n"
              "  docker compose -f lab/docker-compose.yml exec runner "
              "python -m demo.checkpoint1 --lab", file=sys.stderr)
        return 2
    return run(args.lab, args.pausa, args.out)


def _lab_reachable() -> bool:
    try:
        return bool(system_resolver("dvwa.lab.test"))
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    sys.exit(main())

