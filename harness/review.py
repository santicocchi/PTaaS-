"""CLI del Reviewer (change 006, D6). Solo escribe decisiones: no envía tráfico.

    python -m harness.review --engagement <id> --state-dir state list
    python -m harness.review --engagement <id> approve <finding_id> --request <hash> \
        --reviewer <n> --reason "<t>"
    python -m harness.review --engagement <id> reject  <finding_id> --reviewer <n> --reason "<t>"

`--request` es el hash corto que mostró `list`: si la solicitud en cola cambió, la aprobación
se rechaza. Un `reject` sobre una aprobación vigente la revoca. Cada decisión queda en el
registro de aprobaciones y en la bitácora (`hitl.approve` / `hitl.reject`, objetivo = host
del hallazgo, subject = finding_id). Primero se valida todo; si algo falla, no se
escribe nada. La fila del registro y el control de la bitácora se escriben en una sola
transacción del registro (ver `record_decision`): si la bitácora falla, no queda la fila.
"""
from __future__ import annotations

import argparse
import sys
import time

from harness.approvals import ApprovalStore, ReviewError, record_decision
from harness.audit import SqliteAuditLog

ACTIONS = {"approve": "approved", "reject": "rejected"}


def now() -> float:
    return time.time()


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m harness.review")
    p.add_argument("--engagement", required=True)
    p.add_argument("--state-dir", default="state")
    p.add_argument("--audit-dir", default="audit")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="hallazgos en cola y su estado")
    for name in ACTIONS:
        s = sub.add_parser(name)
        s.add_argument("finding_id")
        if name == "approve":                # el hash que mostró `list`: se aprueba lo que se vio
            s.add_argument("--request", required=True)
        s.add_argument("--reviewer", required=True)
        s.add_argument("--reason", required=True)
    return p


def _list(store: ApprovalStore, at: float) -> int:
    print("finding_id\tcwe\thost\tpriority\tpoc_id\tparams\trequest\tstatus")
    for item in store.queue():
        params = ",".join(f"{k}={v}" for k, v in sorted(item.params.items())) or "-"
        priority = "-" if item.priority is None else f"{item.priority:g}"
        print(f"{item.finding_id}\t{item.cwe}\t{item.host}\t{priority}\t"
              f"{item.poc_id or '-'}\t{params}\t{item.request_hash}\t"
              f"{store.status(item.finding_id, at)}")
    return 0


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        store = ApprovalStore.open(args.engagement, args.state_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    at = now()
    if args.command == "list":
        return _list(store, at)
    decision = ACTIONS[args.command]
    try:
        store.check_decision(args.finding_id, decision, args.reviewer, args.reason, at,
                             getattr(args, "request", None))
    except ReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    audit = SqliteAuditLog.open(args.engagement, args.audit_dir)
    try:
        record_decision(store, audit, args.engagement, args.finding_id, decision,
                        args.reviewer, args.reason, at, getattr(args, "request", None))
    except ReviewError as exc:              # cambió entre la validación y la transacción
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - se informa fuerte: registro y bitácora
        print(f"ERROR: la decisión NO quedó registrada ({type(exc).__name__}: {exc}). "
              "Revisá la bitácora antes de reintentar.", file=sys.stderr)
        return 3
    finally:
        audit.close()
    print(f"{args.finding_id}: {decision} por {args.reviewer}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
