"""Demo del loop C (change 006): validación por hallazgo en el sandbox, con gate humano.

    python -m demo.pipeline [--lab]                        # 1. deja la entrega del análisis
    python -m demo.validation [--lab] --engagement <id> \\
        --approve-phase --reviewer <usuario>               # 2. importa, abre VALIDATE y arma
                                                           #    la cola del Reviewer (sin envíos)
    python -m harness.review --engagement <id> \\
        --state-dir demo/state --audit-dir demo/state ...  # 3. el Reviewer aprueba UN hallazgo
    python -m demo.validation [--lab] --engagement <id>    # 4. se valida solo el aprobado

Corre en el host del laboratorio, que es el que tiene docker: el runner no tiene el socket, a
propósito (design.md del 006, D3).

**Dónde vive el estado.** El runner procesa datos hostiles y puede escribir `demo/out` entero
(entrega, bitácora y registros). Por eso `demo/out` es solo la bandeja de entrada: la primera
corrida verifica la entrega y la importa a `demo/state/`, que en el runner es de solo lectura
(el repo se monta `:ro`). La bitácora del loop C, las aprobaciones y las observaciones viven
ahí. Una aprobación escrita en `demo/out` desde el runner no cuenta.

**Qué se verifica al importar:** la cadena de la bitácora de la entrega, que haya un solo
`handoff.written` del orquestador con el SHA-256 del archivo, que el modo (sim o lab) sea el de
esta corrida y que el RoE sea `demo/roe-pipeline.yaml` (que el runner no puede tocar) salvo
`engagement_id`, la ventana y el hash de aprobación. Así no se puede quitar una exclusión ni
agrandar el alcance editando la entrega. Si algo falla, queda `handoff.rejected` en la bitácora
del host y no se envía nada.

**Gates.** VALIDATE exige el gate `before_validate` del Reviewer (`--approve-phase
--reviewer`), que queda en la bitácora como `gate.approve`. Además, cada envío exige la
aprobación del Reviewer para ESE hallazgo con `python -m harness.review`. Sin ella el Harness
registra PENDING_HITL y no se levanta ningún contenedor.

Con `--lab`, cada envío es un `docker run --rm` de la imagen `ptaas-sandbox` en la red `lab_lab`
(internal). En simulación, docker es `SimDocker`: no se ejecuta nada y la respuesta es la del
DVWA del laboratorio, grabada.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import yaml

from demo.checkpoint1 import bad, dim, ok, warn
from demo.loop_a import SIM_DNS
from demo.pipeline import HANDOFF_ACTION, ROE_TEMPLATE, ROOT
from harness.adapters.poc_catalog_adapter import PocCatalogRun
from harness.analysis import FindingStore, Observation
from harness.approvals import REVIEWER_RE, ApprovalStore
from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import Guard, Harness, KillSwitch, Phase, Resolver, Result, ScopeViolation
from harness.engagement import Engagement, State
from harness.evidence import verify_evidence
from harness.poc.catalog import catalog_version, load_catalog
from harness.policy_loader import phase_allowlist
from harness.roe import RoEError, parse_roe
from harness.sandbox import LAB_NETWORK, DockerRunner, DockerSandbox, default_docker_runner
from harness.schemas import CandidateFinding, PrioritizedVuln
from harness.tokens import TokenIssuer
from harness.validation import CAPABILITY, ValidationLoop, ValidationResult

AGENT = "validation-demo"
STATE = ROOT / "state"                    # del host: en el runner es de solo lectura
SANDBOX_IMAGE = "ptaas-sandbox"
SIM_IMAGE = "sha256:" + "0" * 64          # en simulación no hay imagen: nunca se ejecuta
LAB_CIDR = ipaddress.IPv4Network("10.99.0.0/24")
MAX_WINDOW = timedelta(hours=8, minutes=5)          # la que arma demo/checkpoint1.prepare_roe
IMPORTED_ACTION = "handoff.imported"
REJECTED_ACTION = "handoff.rejected"
GATE_ACTION = "gate.approve"
GATE = "before_validate"
IMAGE_ACTION = "sandbox.image"
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}\Z")
_ROE_VARIABLE = ("engagement_id", "window", "approval")

# Respuesta del DVWA del laboratorio a `GET /` (vista en el sandbox real, 2026-11-20), sin el
# cuerpo completo. No tiene Content-Security-Policy ni X-Frame-Options.
SIM_DVWA_HEADERS = [
    ["Date", "Fri, 20 Nov 2026 12:00:00 GMT"],
    ["Server", "Apache/2.4.25 (Debian)"],
    ["Set-Cookie", "PHPSESSID=sim; path=/"],
    ["Set-Cookie", "security=low"],
    ["Content-Type", "text/html;charset=utf-8"],
]
SIM_DVWA_BODY = "<!DOCTYPE html><html><head><title>Login :: Damn Vulnerable Web Application"
_SANDBOX_OPTIONS = ("--rm", "--read-only", "--network", LAB_NETWORK, "--cap-drop", "ALL")


class SimDocker:
    """`docker` simulado: ps, network inspect, run y rm. Registra lo que se habría enviado.

    También exige las opciones fijas del contenedor, así la simulación detecta si alguna se
    pierde (revisión m7)."""

    runs: ClassVar[list[dict[str, Any]]] = []

    def __call__(self, argv: list[str], stdin: str | None, timeout_s: int) -> tuple[int, str]:
        if argv[:3] == ["docker", "network", "inspect"]:
            return 0, "true\n"
        if argv[:2] == ["docker", "ps"]:
            return 0, ""                           # --rm: no quedan contenedores
        if argv[:2] == ["docker", "rm"]:
            return 0, argv[-1]
        if argv[:2] == ["docker", "run"]:
            missing = [o for o in _SANDBOX_OPTIONS if o not in argv]
            if missing or argv[-1] != SIM_IMAGE:
                raise AssertionError(f"docker run sin sus opciones fijas: {missing}")
            SimDocker.runs.append(json.loads(stdin or "{}"))
            return 0, json.dumps({"ok": True, "status": 200, "headers": SIM_DVWA_HEADERS,
                                  "body": SIM_DVWA_BODY, "truncated": False})
        raise AssertionError(f"comando de docker inesperado: {argv}")


# ---- laboratorio real --------------------------------------------------------------------

def lab_network_ok(runner: DockerRunner) -> bool:
    """`lab_lab` existe, es internal y su subred está dentro de 10.99.0.0/24."""
    code, out = runner(["docker", "network", "inspect", "--format",
                        "{{json .Internal}} {{json .IPAM.Config}}", LAB_NETWORK], None, 20)
    if code != 0:
        return False
    internal, _, ipam = out.strip().partition(" ")
    try:
        subnets = [ipaddress.ip_network(c["Subnet"]) for c in json.loads(ipam) or []]
    except (ValueError, KeyError, TypeError):
        return False
    v4 = [n for n in subnets if isinstance(n, ipaddress.IPv4Network)]
    return internal == "true" and bool(subnets) and len(v4) == len(subnets) and all(
        n.subnet_of(LAB_CIDR) for n in v4)


def lab_resolver(runner: DockerRunner) -> Resolver:
    """Nombres `*.lab.test` según los alias de la red `lab_lab` (los resuelve docker).

    En el host no hay DNS para `*.lab.test`: se arma una tabla fija al arrancar con los alias y
    la IP de cada contenedor de esa red. Solo entran alias `.lab.test` con IP del laboratorio;
    el Guard igual vuelve a exigir que la IP esté en el alcance del token.
    """
    code, out = runner(["docker", "network", "inspect", "--format",
                        "{{range $id, $c := .Containers}}{{$id}} {{end}}", LAB_NETWORK],
                       None, 20)
    table: dict[str, list[str]] = {}
    for cid in out.split() if code == 0 else []:
        if not _CONTAINER_ID_RE.match(cid):
            continue
        code, info = runner(["docker", "inspect", "--format",
                             '{{json (index .NetworkSettings.Networks "' + LAB_NETWORK + '")}}',
                             cid], None, 20)
        try:
            net = json.loads(info) if code == 0 else None
            ip = ipaddress.ip_address(net["IPAddress"]) if isinstance(net, dict) else None
        except (ValueError, KeyError, TypeError):
            continue
        if net is None or ip is None or ip not in LAB_CIDR:
            continue
        for alias in net.get("Aliases") or []:
            if isinstance(alias, str) and alias.endswith(".lab.test"):
                table.setdefault(alias, []).append(str(ip))
    return lambda host: list(table.get(host, []))


def sandbox_image(runner: DockerRunner) -> str | None:
    code, out = runner(["docker", "image", "inspect", SANDBOX_IMAGE, "--format", "{{.Id}}"],
                       None, 20)
    return out.strip() if code == 0 else None


# ---- entrega del análisis ------------------------------------------------------------------

class HandoffError(Exception):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _template_part(roe: dict[str, Any]) -> dict[str, Any]:
    part = {k: v for k, v in roe.items() if k not in _ROE_VARIABLE}
    part["approver"] = (roe.get("approval") or {}).get("approver")
    return part


def check_roe(roe: dict[str, Any], eng: str, now: datetime) -> None:
    """El RoE de la entrega es la plantilla del repo, con su engagement y una ventana sana."""
    template = yaml.safe_load(ROE_TEMPLATE.read_text(encoding="utf-8"))
    if _template_part(roe) != _template_part(template):
        raise HandoffError("el RoE de la entrega no es el de demo/roe-pipeline.yaml")
    if roe.get("engagement_id") != eng:
        raise HandoffError("la entrega es de otro engagement")
    try:
        start = datetime.fromisoformat(roe["window"]["start"])
        end = datetime.fromisoformat(roe["window"]["end"])
        sane = start <= now and end - start <= MAX_WINDOW
    except (KeyError, TypeError, ValueError) as exc:
        raise HandoffError("ventana del RoE inválida") from exc
    if not sane:
        raise HandoffError("ventana del RoE fuera de lo que arma la demo")


def verify_inbox(inbox: Path, eng: str, lab: bool, now: datetime) -> tuple[bytes, dict[str, Any]]:
    """Verifica la entrega de demo/out. Lanza HandoffError con el motivo."""
    path, audit_path = inbox / f"{eng}.handoff.json", inbox / f"{eng}.sqlite3"
    if not path.is_file() or not audit_path.is_file():
        raise HandoffError(f"no hay entrega del análisis para {eng} en {inbox}: primero corré "
                           "python -m demo.pipeline")
    error = verify_file(audit_path)
    if error is not None:
        raise HandoffError(f"la bitácora de la entrega no está íntegra: {error}")
    raw = path.read_bytes()
    audit = SqliteAuditLog.open(eng, inbox)
    try:
        refs = [e for e in audit.entries if e["phase"] == "control"
                and e["action"] == HANDOFF_ACTION]
    finally:
        audit.close()
    if len(refs) != 1 or refs[0]["agent"] != "orchestrator" or refs[0]["target"] != path.name:
        raise HandoffError("la bitácora tiene que registrar una sola entrega, del orquestador")
    if refs[0].get("evidence") != f"{path.name}#sha256={_sha(raw)}":
        raise HandoffError("la entrega no coincide con la bitácora (¿se modificó?)")
    data: dict[str, Any] = json.loads(raw)
    if data.get("engagement_id") != eng:
        raise HandoffError("la entrega es de otro engagement")
    if data.get("mode") != ("lab" if lab else "sim"):
        raise HandoffError(f"la entrega es de modo {data.get('mode')!r}: no se mezcla "
                           "simulación con laboratorio")
    check_roe(data["roe"], eng, now)
    return raw, data


def import_handoff(state: Path, eng: str, raw: bytes, data: dict[str, Any],
                   audit: SqliteAuditLog) -> None:
    """Copia la entrega y sus observaciones a demo/state y deja su hash en la bitácora."""
    path = state / f"{eng}.handoff.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    store = FindingStore.open(eng, state)
    try:
        for o in data["observations"]:
            store.add(Observation(**o))
    finally:
        store.close()
    audit.record_control(eng, AGENT, IMPORTED_ACTION, path.name, Result.OK,
                         evidence=f"{path.name}#sha256={_sha(raw)}")


def load_imported(state: Path, eng: str, audit: SqliteAuditLog) -> dict[str, Any]:
    path = state / f"{eng}.handoff.json"
    raw = path.read_bytes()
    refs = [e["evidence"] for e in audit.entries
            if e["phase"] == "control" and e["action"] == IMPORTED_ACTION]
    if refs != [f"{path.name}#sha256={_sha(raw)}"]:
        raise HandoffError("la entrega importada no coincide con la bitácora del host")
    data: dict[str, Any] = json.loads(raw)
    return data


def findings(data: dict[str, Any]) -> tuple[list[CandidateFinding], list[PrioritizedVuln]]:
    candidates = [CandidateFinding(**c) for c in data["candidates"]]
    vulns = [PrioritizedVuln(**{**v, "evidence_refs": tuple(v["evidence_refs"])})
             for v in data["vulns"]]
    return candidates, vulns


def gate_reviewer(audit: SqliteAuditLog, eng: str) -> str | None:
    for e in reversed(audit.entries):
        if (e["engagement"], e["phase"], e["action"], e["target"], e["result"]) == (
                eng, "control", GATE_ACTION, GATE, Result.OK.value):
            return str(e["agent"]).removeprefix("reviewer:")
    return None


def engagement_in_validate() -> Engagement:
    """El engagement de la demo hasta VALIDATE. El estado no se persiste en este TP: se
    recorre la máquina de estados con sus gates. `first_active_action` lo aprobó el pipeline y
    `before_validate` está en la bitácora del host (lo comprueba quien llama)."""
    engagement = Engagement(roe_valid=True)
    engagement.approve("first_active_action")
    while engagement.state != State.ANALYZE:
        engagement.advance()
    engagement.approve(GATE)
    engagement.advance()
    return engagement


def _printable(text: str) -> str:
    """Lo que viene del objetivo no puede mover el cursor ni pintar la pantalla del Reviewer."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)


def _shown(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _err(msg: str) -> int:
    print(bad(msg), file=sys.stderr)
    return 2


# ---- la demo -------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loop C: validación por hallazgo en sandbox")
    parser.add_argument("--engagement", required=True)
    parser.add_argument("--lab", action="store_true", help="sandbox real (docker en el host)")
    parser.add_argument("--inbox", type=Path, default=ROOT / "out",
                        help="donde dejó la entrega el pipeline (default demo/out)")
    parser.add_argument("--state", type=Path, default=STATE,
                        help="estado del loop C en el host (default demo/state)")
    parser.add_argument("--approve-phase", action="store_true",
                        help="el Reviewer aprueba el gate before_validate (una vez)")
    parser.add_argument("--reviewer", help="quién aprueba el gate before_validate")
    args = parser.parse_args(argv)
    eng, state = args.engagement, args.state
    if not _ENGAGEMENT_RE.match(eng):
        return _err(f"engagement inválido: {eng!r}")
    if args.approve_phase and not (args.reviewer and REVIEWER_RE.match(args.reviewer)):
        return _err("--approve-phase necesita --reviewer <usuario> (letras, números, . @ _ -)")

    runner: DockerRunner = default_docker_runner if args.lab else SimDocker()
    if args.lab and not lab_network_ok(runner):
        return _err(f"La red {LAB_NETWORK} no existe, no es internal o su subred no es "
                    f"{LAB_CIDR}: levantá el laboratorio (lab/README.md) y corré esto en su "
                    "host, con docker.")
    image = sandbox_image(runner) if args.lab else SIM_IMAGE
    if image is None:
        return _err(f"Falta la imagen {SANDBOX_IMAGE}: docker compose -f "
                    "lab/docker-compose.yml --profile build build sandbox")

    # 1. Entrega: se importa una sola vez; después solo cuenta la copia del host.
    state.mkdir(parents=True, exist_ok=True)
    audit_path = state / f"{eng}.sqlite3"
    if audit_path.exists() and (error := verify_file(audit_path)) is not None:
        return _err(f"La bitácora del host no está íntegra, no se valida nada: {error}")
    audit = SqliteAuditLog.open(eng, state)
    try:
        if not (state / f"{eng}.handoff.json").exists():
            try:
                raw, data = verify_inbox(args.inbox, eng, args.lab,
                                         datetime.now().astimezone())
            except (HandoffError, KeyError, TypeError, ValueError) as exc:
                audit.record_control(eng, AGENT, REJECTED_ACTION, f"{eng}.handoff.json",
                                     Result.ABORTED)
                audit.close()
                return _err(f"No se importa la entrega: {exc}")
            import_handoff(state, eng, raw, data, audit)
            print(dim(f"   entrega importada a {_shown(state)} (SHA-256 {_sha(raw)[:12]}…)"))
        data = load_imported(state, eng, audit)
        if data.get("mode") != ("lab" if args.lab else "sim"):
            raise HandoffError(f"la entrega importada es de modo {data.get('mode')!r}: no se "
                               "mezcla simulación con laboratorio")

        # 2. Gate before_validate del Reviewer, en la bitácora del host.
        if args.approve_phase and gate_reviewer(audit, eng) is None:
            audit.record_control(eng, f"reviewer:{args.reviewer}", GATE_ACTION, GATE,
                                 Result.OK)
        reviewer = gate_reviewer(audit, eng)
        if reviewer is None:
            audit.close()
            print(warn(f"Falta el gate {GATE}: el Reviewer abre la fase de validación con\n"
                       f"  python -m demo.validation{' --lab' if args.lab else ''} "
                       f"--engagement {eng} --approve-phase --reviewer <tu-usuario>"))
            return 0

        resolver: Resolver = (lab_resolver(runner) if args.lab
                              else (lambda h: SIM_DNS.get(h, [])))
        roe = parse_roe(data["roe"])
        candidates, vulns = findings(data)
        # El mismo resolver para el Guard y para el emisor: así la IP de un host excluido por
        # nombre (juiceshop.lab.test) queda fijada en el token también desde el host.
        issuer = TokenIssuer(audit, resolver=resolver)
        token = issuer.issue(roe, Phase.VALIDATE)
    except (HandoffError, RoEError, ScopeViolation, KeyError, TypeError, ValueError) as exc:
        audit.close()
        return _err(f"No se puede validar: {exc}")

    audit.record_control(eng, AGENT, IMAGE_ACTION, image, Result.OK)    # qué imagen corrió
    catalog = load_catalog()
    sandbox = DockerSandbox(eng, catalog, image=image, runner=runner)
    adapter = PocCatalogRun(sandbox, catalog, state_dir=state, catalog_version=catalog_version())
    harness = Harness(Guard(phase_allowlist()), audit, {CAPABILITY: adapter}, KillSwitch(),
                      issuer, resolver=resolver)
    store = FindingStore.open(eng, state)
    approvals = ApprovalStore.open(eng, state)

    mode = "LABORATORIO REAL (sandbox docker)" if args.lab else "SIMULACIÓN (docker simulado)"
    print(f"Loop C · {eng} · {mode}")
    print(dim(f"   catálogo {catalog_version()}, imagen {image[:19]}…, red {LAB_NETWORK} "
              "(internal)"))
    print(dim(f"   gate {GATE}: aprobado por {_printable(reviewer)} (en la bitácora)"))
    loop = ValidationLoop(harness, token, store, engagement=engagement_in_validate(),
                          catalog=catalog, approvals=approvals)
    try:
        result = loop.run(vulns, candidates)
        _show(result, candidates, approvals, eng, state)
    finally:
        store.close()
        approvals.close_connection()

    _show_audit(audit)
    audit.close()
    error = verify_file(audit_path)
    print(ok("OK: cadena íntegra") if error is None else bad(f"CADENA ROTA: {error}"))
    return 0 if error is None else 1


def _show(result: ValidationResult, candidates: list[CandidateFinding],
          approvals: ApprovalStore, eng: str, state: Path) -> None:
    by_id = {c.id: c for c in candidates}
    print(f"\n   {result.reason}; {len(result.outcomes)} hallazgos\n")
    print(dim(f"   {'hallazgo':<18} {'estado':<14} {'motivo':<30} {'qué':<16} {'host':<20} "
              "verificación"))
    pending = []
    for fid, o in result.outcomes.items():
        c = by_id[fid]
        paint = {"validated": ok, "pending_hitl": warn, "failed": bad}.get(o.status, dim)
        print(f"   {fid:<18} {paint(f'{o.status:<14}')} {(o.reason or '-')[:30]:<30} "
              f"{_printable(c.cve or c.cwe):<16} {_printable(c.host):<20} {o.poc_id or '-'}")
        if o.status == "pending_hitl":
            pending.append(fid)
        for ref in o.evidence_refs:
            mark = ok("íntegra") if verify_evidence(state, ref) else bad("NO coincide")
            print(dim(f"      evidencia {_printable(ref)[:60]}… {mark}"))
    if not pending:
        return
    print("\nPendientes del Reviewer. Revisá la solicitud (host, verificación y parámetros) y "
          "aprobá UNA por vez:")
    for fid in pending:
        item = approvals.item(fid)
        assert item is not None
        params = ", ".join(f"{k}={v}" for k, v in sorted(item.params.items()))
        print(f"   {fid}: {item.poc_id} sobre {_printable(item.host)} ({_printable(params)})")
        print(f"     python -m harness.review --engagement {eng} --state-dir {_shown(state)} "
              f"--audit-dir {_shown(state)} approve {fid} --request {item.request_hash} "
              f'--reviewer <tu-usuario> --reason "<por qué>"')
    print(dim("   Después volvé a correr este comando: se envía solo lo aprobado."))


def _show_audit(audit: SqliteAuditLog) -> None:
    entries = audit.entries
    keep = ("hitl.approve", "hitl.reject", "validation.attempt", "validation.closed",
            "sandbox.cleanup_failed", GATE_ACTION, IMPORTED_ACTION)
    print("\nBitácora del loop C (demo/state):")
    no_entry = [e for e in entries if e["action"] == "validation.closed"
                and e.get("reason") == "no_catalog_entry"]
    if no_entry:
        print(dim(f"   control  validation.closed × {len(no_entry)} (no_catalog_entry: el catálogo "
                  "no tiene verificación para ese CWE y host; no se envió nada)"))
    for e in entries:
        if e in no_entry:
            continue
        if e["phase"] == "validate" or e["action"] in keep:
            who = f" [{e['subject']}]" if e.get("subject") else ""
            print(dim(f"   {e['phase']:<8} {e['action']:<28} {_printable(e['target']):<16} "
                      f"{e['result']:<12} {e.get('reason') or ''}{who}"))


if __name__ == "__main__":
    sys.exit(main())
