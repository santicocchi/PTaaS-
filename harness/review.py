"""CLI del Reviewer (change 006, D6). Solo escribe decisiones: no envía tráfico.

    python -m harness.review --engagement <id> --state-dir state list
    python -m harness.review --engagement <id> approve <finding_id> --reviewer <n> --reason "<t>"
    python -m harness.review --engagement <id> reject  <finding_id> --reviewer <n> --reason "<t>"

Cada decisión queda en el registro de aprobaciones y en la bitácora (`hitl.approve` /
`hitl.reject`, objetivo = host del hallazgo). Primero se valida todo; si algo falla, no se
escribe nada. Después se escribe la bitácora y recién entonces el registro.
"""
from __future__ import annotations

import argparse
import sys
import time

from harness.approvals import ApprovalStore, ReviewError
from harness.audit import SqliteAuditLog
from harness.contracts import Result

ACTIONS = {"approve": ("approved", "hitl.approve"), "reject": ("rejected", "hitl.reject")}


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
        s.add_argument("--reviewer", required=True)
        s.add_argument("--reason", required=True)
    return p


def _list(store: ApprovalStore, at: float) -> int:
    print("finding_id\tcwe\thost\tpriority\tpoc_id\tparams\tstatus")
    for item in store.queue():
        params = ",".join(f"{k}={v}" for k, v in sorted(item.params.items())) or "-"
        priority = "-" if item.priority is None else f"{item.priority:g}"
        print(f"{item.finding_id}\t{item.cwe}\t{item.host}\t{priority}\t"
              f"{item.poc_id or '-'}\t{params}\t{store.status(item.finding_id, at)}")
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
    decision, control = ACTIONS[args.command]
    try:
        item = store.check_decision(args.finding_id, decision, args.reviewer, args.reason, at)
    except ReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    audit = SqliteAuditLog.open(args.engagement, args.audit_dir)
    try:
        audit.record_control(args.engagement, f"reviewer:{args.reviewer}", control, item.host,
                             Result.OK)
    finally:
        audit.close()
    store.decide(args.finding_id, decision, args.reviewer, args.reason, at)
    print(f"{args.finding_id}: {decision} por {args.reviewer}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
