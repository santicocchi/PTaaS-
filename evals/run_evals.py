#!/usr/bin/env python3
"""Evals por agente.

  python evals/run_evals.py --mode golden                      # casos + rúbrica (offline, CI)
  python evals/run_evals.py --mode live                        # llama al modelo (API key)
  python evals/run_evals.py --mode live --agent correlation --report evals/out/live.json

`live` carga el prompt de `prompts/` y el modelo de `harness/models.yaml`, manda la entrada del
caso y puntúa la respuesta con la misma rúbrica que `golden`. La clave sale de
`ANTHROPIC_API_KEY` (nunca del repo). Cada corrida en vivo puede guardar un informe JSON con la
respuesta cruda, las violaciones y el uso de tokens: es la base del informe de evals.

Ningún caso toca activos: la entrada son datos del caso y la salida es texto. Los agentes con
`model: null` (Scope Guard, Reviewer) no se evalúan en vivo porque no son un LLM.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from evals.rubric import score

PROMPT_FILES = {
    "orchestrator": "00-orchestrator.md", "correlation": "03-correlation.md",
    "validation": "05-validation.md", "vuln_analysis": "04-vuln-analysis.md",
    "asset_discovery": "02-asset-discovery.md", "reporting": "06-reporting.md",
}


def load_cases(agent: str | None = None) -> list[dict]:
    cases = []
    for f in sorted((ROOT / "evals" / "cases").glob("*.json")):
        cases += json.loads(f.read_text(encoding="utf-8"))
    return [c for c in cases if agent in (None, c["agent"])]


def run_golden(cases: list[dict]) -> dict[str, list[str]]:
    return {c["id"]: score(c, c["golden_output"]) for c in cases}


_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


def parse_json_reply(text: str) -> dict[str, Any] | None:
    """La respuesta del modelo → objeto JSON. Acepta un bloque ```json``` y nada más."""
    text = text.strip()
    m = _FENCE.match(text)
    try:
        out = json.loads(m.group(1) if m else text)
    except json.JSONDecodeError:
        return None
    return out if isinstance(out, dict) else None


def run_live(cases: list[dict], client: Any = None,
             report: list[dict[str, Any]] | None = None) -> dict[str, list[str]]:
    models = yaml.safe_load((ROOT / "harness" / "models.yaml").read_text())["agents"]
    if client is None:
        import anthropic  # pip install anthropic

        client = anthropic.Anthropic()
    results: dict[str, list[str]] = {}
    for c in cases:
        cfg = models[c["agent"]]
        if not cfg.get("model"):
            continue                                  # código determinista o humano
        system = (ROOT / "prompts" / PROMPT_FILES[c["agent"]]).read_text(encoding="utf-8")
        entry: dict[str, Any] = {"id": c["id"], "agent": c["agent"], "model": cfg["model"]}
        try:
            msg = client.messages.create(
                model=cfg["model"], max_tokens=cfg["max_tokens"],
                temperature=cfg["temperature"],
                system=system + "\nRespondé únicamente con un objeto JSON válido, sin texto "
                                "alrededor.",
                messages=[{"role": "user",
                           "content": json.dumps(c["input"], ensure_ascii=False)}])
        except Exception as exc:                      # noqa: BLE001 — un caso no corta la corrida
            results[c["id"]] = [f"error de la API: {type(exc).__name__}"]
            entry["violations"] = results[c["id"]]
            if report is not None:
                report.append(entry)
            continue
        text = "".join(b.text for b in msg.content if getattr(b, "text", None))
        out = parse_json_reply(text)
        results[c["id"]] = (["la salida no es un objeto JSON válido"] if out is None
                            else score(c, out))
        usage = getattr(msg, "usage", None)
        entry.update(raw=text, violations=results[c["id"]],
                     input_tokens=getattr(usage, "input_tokens", None),
                     output_tokens=getattr(usage, "output_tokens", None))
        if report is not None:
            report.append(entry)
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["golden", "live"], default="golden")
    ap.add_argument("--agent")
    ap.add_argument("--report", type=Path, help="(live) guardar respuestas y violaciones en JSON")
    args = ap.parse_args(argv)
    cases = load_cases(args.agent)
    if args.mode == "live" and not os.environ.get("ANTHROPIC_API_KEY"):
        print("Falta ANTHROPIC_API_KEY en el entorno: el modo live llama al modelo.",
              file=sys.stderr)
        return 2
    report: list[dict[str, Any]] = []
    results = run_golden(cases) if args.mode == "golden" else run_live(cases, report=report)
    if args.report and args.mode == "live":
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n",
                               encoding="utf-8")
    failed = {k: v for k, v in results.items() if v}
    for k, v in results.items():
        print(("FAIL " if v else "PASS ") + k, *v, sep=" | " if v else "")
    print(f"\n{len(results) - len(failed)}/{len(results)} casos aprobados")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
