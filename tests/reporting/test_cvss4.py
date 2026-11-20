"""Change 007 · reporting: vector CVSS v4.0 válido y sin LLM (D4)."""
import pytest

from harness.cvss4 import InvalidVector, parse_vector, severity

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_vector_valido():
    v = parse_vector(BASE)
    assert v.text == BASE
    assert v.metrics["AV"] == "N" and v.metrics["SA"] == "N" and len(v.metrics) == 11


def test_vector_con_opcionales_en_orden():
    text = BASE + "/E:A/CR:H/MAV:L/MSI:S/S:P/AU:Y/R:A/V:C/RE:H/U:Red"
    assert parse_vector(text).metrics["U"] == "Red"


@pytest.mark.parametrize("text", [
    BASE + "/basura",                                          # cola inventada
    BASE + "/",                                                # separador vacío
    "CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # duplicada
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",           # falta SA
    "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",      # fuera de orden
    "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",      # valor no permitido
    BASE + "\n",                                               # salto de línea final
    " " + BASE,
    BASE.lower(),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",           # vector 3.1
    BASE + "/U:red",                                           # minúscula en el valor
    BASE + "/S:P/E:A",                                         # opcionales fuera de orden
    BASE + "/E:A/E:A",                                         # opcional duplicada
    BASE + "/MSC:S",                                           # S solo vale en MSI y MSA
    "",
])
def test_vector_invalido(text):
    with pytest.raises(InvalidVector):
        parse_vector(text)


def test_no_es_texto():
    with pytest.raises(InvalidVector):
        parse_vector(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("score,label", [
    (0.0, "None"), (0.1, "Low"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"),
    (7.0, "High"), (8.9, "High"), (9.0, "Critical"), (10.0, "Critical"),
])
def test_severidad_por_puntaje(score, label):
    assert severity(score) == label


@pytest.mark.parametrize("text,score,label", [
    # Puntajes de la calculadora de FIRST (https://www.first.org/cvss/calculator/4.0).
    (BASE, 9.3, "Critical"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "None"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.3, "Medium"),
])
def test_puntaje_de_first(text, score, label):
    v = parse_vector(text)
    assert (v.score, v.severity) == (score, label)
