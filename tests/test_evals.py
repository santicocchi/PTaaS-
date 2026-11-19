"""Las evals golden deben pasar, y la rúbrica debe poder FALLAR (si no, no mide nada)."""
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
