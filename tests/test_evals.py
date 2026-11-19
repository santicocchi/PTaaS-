"""Las evals golden deben pasar, y la rúbrica debe poder FALLAR (si no, no mide nada)."""
import json

import pytest

from evals.rubric import score
from evals.run_evals import load_cases, run_golden


def test_todos_los_casos_golden_pasan():
    res = run_golden(load_cases())
    assert len(res) >= 10
    assert {k: v for k, v in res.items() if v} == {}


def test_hay_casos_para_los_agentes_con_llm_criticos():
    agentes = {c["agent"] for c in load_cases()}
    assert {"orchestrator", "correlation", "validation", "vuln_analysis"} <= agentes


def test_la_rubrica_detecta_una_salida_mala():
    caso = next(c for c in load_cases() if c["id"] == "val-001-solo-catalogo")
    mala = {"poc_id": "POC-NEW-1", "parameters": {"payload": "<script>"}}
    fallas = score(caso, mala)
    assert any("poc_id" in f for f in fallas) and any("prohibido" in f for f in fallas)


def test_la_rubrica_detecta_cve_inventado():
    caso = next(c for c in load_cases() if c["id"] == "corr-001-sin-cve-no-inventa")
    assert score(caso, {"candidates": [{"cve": "CVE-2020-9999"}]})


# --- change 005: casos nuevos de correlación y análisis ---------------------------------
def _case(case_id):
    import json
    from pathlib import Path
    for f in (Path(__file__).parents[1] / "evals" / "cases").glob("*.json"):
        for c in json.loads(f.read_text(encoding="utf-8")):
            if c["id"] == case_id:
                return c
    raise KeyError(case_id)


def test_rubrica_navega_listas():
    caso = _case("corr-004-banner-debian-confianza-baja")
    mala = {"candidates": [{**caso["golden_output"]["candidates"][0], "confidence": "medium"}]}
    assert any("candidates.0.confidence" in f for f in score(caso, mala))
    assert score(caso, {"candidates": []})


def test_version_sola_confirmada_falla_la_eval():
    caso = _case("vuln-006-version-sola-no-confirma")
    assert score(caso, {**caso["golden_output"], "status": "confirmed"})


def test_contradiccion_descartada_falla_la_eval():
    caso = _case("vuln-003-contradiccion-zap-nuclei")
    assert score(caso, {**caso["golden_output"], "status": "discarded"})


def test_hay_al_menos_doce_casos_de_correlacion_y_analisis():
    import json
    from pathlib import Path
    base = Path(__file__).parents[1] / "evals" / "cases"
    n = sum(len(json.loads((base / f).read_text())) for f in ("correlation.json",
                                                                "vuln_analysis.json"))
    assert n >= 12


# --- Checkpoint 2: ≥ 20 casos y modo live probado con un cliente falso -----------------
def test_hay_al_menos_veinte_casos_y_todos_los_agentes_con_llm():
    from evals.run_evals import PROMPT_FILES

    cases = load_cases()
    assert len(cases) >= 20
    assert {"orchestrator", "asset_discovery", "correlation", "vuln_analysis",
            "validation"} <= {c["agent"] for c in cases}
    assert {c["agent"] for c in cases} <= set(PROMPT_FILES)


def test_sondear_un_host_fuera_de_alcance_falla_la_eval():
    caso = _case("asset-001-descubrimiento-fuera-de-alcance")
    mala = {**caso["golden_output"],
            "next_actions": [{"capability": "httpx.probe", "target": "cdn.example.com"}]}
    assert any("prohibido" in f for f in score(caso, mala))


def test_planificar_una_fase_no_autorizada_falla_la_eval():
    caso = _case("orch-003-fase-no-autorizada")
    mala = {**caso["golden_output"],
            "phases": [*caso["golden_output"]["phases"], {"phase": "validate"}]}
    assert score(caso, mala)


class _Block:
    def __init__(self, text):
        self.text = text


class _Msg:
    def __init__(self, text):
        self.content = [_Block(text)]
        self.usage = type("U", (), {"input_tokens": 10, "output_tokens": 5})()


class _FakeClient:
    """Contesta cada caso con su salida golden, en distintos formatos."""

    def __init__(self, cases, mode):
        self.by_input = {json.dumps(c["input"], ensure_ascii=False): c for c in cases}
        self.mode, self.calls = mode, []
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        case = self.by_input[kw["messages"][0]["content"]]
        if self.mode == "error":
            raise RuntimeError("sin red")
        body = json.dumps(case["golden_output"], ensure_ascii=False)
        return _Msg({"plain": body, "fence": f"```json\n{body}\n```",
                     "prosa": f"Acá va: {body}"}[self.mode])


@pytest.mark.parametrize("mode,ok", [("plain", True), ("fence", True), ("prosa", False)])
def test_modo_live_puntua_con_la_misma_rubrica(mode, ok):
    from evals.run_evals import run_live

    cases = load_cases()
    report = []
    client = _FakeClient(cases, mode)
    res = run_live(cases, client=client, report=report)
    assert len(res) == len(cases) and (not any(res.values())) is ok
    assert all(c["system"].startswith("# Agente") for c in client.calls)
    assert {e["id"] for e in report} == set(res) and report[0]["input_tokens"] == 10


def test_modo_live_un_error_de_la_api_no_corta_la_corrida():
    from evals.run_evals import run_live

    cases = load_cases()
    res = run_live(cases, client=_FakeClient(cases, "error"))
    assert len(res) == len(cases)
    assert all(v == ["error de la API: RuntimeError"] for v in res.values())


def test_modo_live_sin_clave_no_llama(monkeypatch, capsys):
    from evals import run_evals

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run_evals.main(["--mode", "live"]) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


@pytest.mark.parametrize("text,expected", [
    ('{"a": 1}', {"a": 1}), ('```json\n{"a": 1}\n```', {"a": 1}), ("[1, 2]", None),
    ("no es json", None), ('```\n{"a": 2}\n```', {"a": 2}),
])
def test_parse_json_reply(text, expected):
    from evals.run_evals import parse_json_reply

    assert parse_json_reply(text) == expected
