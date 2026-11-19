"""Scenarios del delta `authorization` del change 003: RoE y emisión de scope tokens."""
import ast
import copy
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from harness.contracts import (
    AuditLog,
    Guard,
    Harness,
    KillSwitch,
    Phase,
    Result,
    ScopeToken,
    ScopeViolation,
)
from harness.policy_loader import load_policy, phase_allowlist
from harness.roe import RoEError, parse_roe, roe_digest
from harness.tokens import TokenIssuer
from tests.conftest import FakeAdapter, act, fake_dns

ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 11, 20, 15, 0, tzinfo=UTC)          # 12:00 en Buenos Aires


def roe_data(**overrides) -> dict:
    """RoE válido de laboratorio. `approval.roe_sha256` se recalcula salvo que se pase."""
    data = {
        "engagement_id": "lab-2026-001",
        "client": "Laboratorio propio",
        "scope": {"cidrs": ["10.99.0.0/24"], "domains": ["dvwa.lab.test", "juiceshop.lab.test"]},
        "exclusions": {"hosts": ["10.99.0.1"], "domains": []},
        "window": {"start": datetime(2026, 11, 20, 9, 0, tzinfo=timezone_ba()),
                   "end": datetime(2026, 11, 20, 18, 0, tzinfo=timezone_ba())},
        "phases": ["recon", "correlate", "analyze", "validate", "report"],
        "emergency_contacts": [{"name": "Santi", "channel": "tel:+540000000"}],
    }
    tamper = overrides.pop("_tamper", None)
    data.update(overrides)
    data["approval"] = {"approver": "Docente", "approved_at": "2026-11-19T12:00:00-03:00",
                        "roe_sha256": roe_digest(data)}
    if tamper:
        tamper(data)
    return data


def timezone_ba():
    from datetime import timezone
    return timezone(timedelta(hours=-3))


@pytest.fixture
def audit():
    return AuditLog()


@pytest.fixture
def issuer(audit):
    return TokenIssuer(audit, key=b"k" * 32)


def _harness(issuer, audit):
    adapters = {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))}
    return Harness(Guard(phase_allowlist()), audit, adapters, KillSwitch(), issuer,
                   resolver=fake_dns), adapters


# --- RoE completo y aprobado -------------------------------------------------

def test_roe_valido_se_parsea():
    roe = parse_roe(roe_data())
    assert roe.engagement_id == "lab-2026-001"
    assert roe.window_start == datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


def test_roe_sin_alcance_ni_contactos_devuelve_un_error_por_campo():
    data = roe_data()
    del data["scope"]
    data["emergency_contacts"] = []
    data["approval"]["roe_sha256"] = roe_digest(data)
    with pytest.raises(RoEError) as exc:
        parse_roe(data)
    campos = " ".join(exc.value.errors)
    assert "scope" in campos and "emergency_contacts" in campos
    assert exc.value.code == "roe_invalid"


def test_roe_modificado_despues_de_aprobado():
    data = roe_data(_tamper=lambda d: d["scope"]["cidrs"].append("10.99.0.128/25"))
    with pytest.raises(RoEError) as exc:
        parse_roe(data)
    assert exc.value.code == "roe_tampered"


def test_roe_desde_yaml(tmp_path):
    import yaml
    data = roe_data()
    texto = yaml.safe_dump(data, sort_keys=False)
    assert parse_roe(texto).engagement_id == "lab-2026-001"


# --- Alcance máximo del laboratorio ------------------------------------------

@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "10.0.0.0/8", "8.8.8.8/32", "10.99.1.0/24"])
def test_cidr_fuera_del_laboratorio_se_rechaza(cidr):
    with pytest.raises(RoEError) as exc:
        parse_roe(roe_data(scope={"cidrs": [cidr], "domains": []}))
    assert cidr in " ".join(exc.value.errors)


def test_dominio_fuera_del_laboratorio_se_rechaza():
    with pytest.raises(RoEError):
        parse_roe(roe_data(scope={"cidrs": [], "domains": ["example.com"]}))


# --- Ventana en UTC ----------------------------------------------------------

def test_ventana_invertida_se_rechaza():
    w = {"start": datetime(2026, 11, 20, 18, tzinfo=UTC), "end": datetime(2026, 11, 20, 9, tzinfo=UTC)}
    with pytest.raises(RoEError):
        parse_roe(roe_data(window=w))


def test_fecha_sin_zona_horaria_se_rechaza():
    sin_zona = datetime(2026, 11, 20, 9)  # noqa: DTZ001 - es justamente el caso a probar
    w = {"start": sin_zona, "end": datetime(2026, 11, 20, 18, tzinfo=UTC)}
    with pytest.raises(RoEError) as exc:
        parse_roe(roe_data(window=w))
    assert "zona" in " ".join(exc.value.errors)


def test_ventana_de_mas_de_siete_dias_se_rechaza():
    w = {"start": datetime(2026, 11, 1, tzinfo=UTC), "end": datetime(2026, 11, 20, tzinfo=UTC)}
    with pytest.raises(RoEError):
        parse_roe(roe_data(window=w))


def test_mismo_instante_en_zonas_distintas(issuer):
    ba = roe_data()
    utc = roe_data(window={"start": datetime(2026, 11, 20, 12, tzinfo=UTC),
                           "end": datetime(2026, 11, 20, 21, tzinfo=UTC)})
    t1 = issuer.issue(parse_roe(ba), Phase.RECON, now=NOW)
    t2 = issuer.issue(parse_roe(utc), Phase.RECON, now=NOW)
    assert (t1.window_start, t1.window_end) == (t2.window_start, t2.window_end)


# --- Exclusiones -------------------------------------------------------------

def test_host_excluido_dentro_del_cidr_se_bloquea(issuer, audit, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    h, adapters = _harness(issuer, audit)
    t = issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.1", t)
    assert audit.entries[-1]["reason"] == "excluded"
    h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.5", t)
    assert adapters["httpx.probe"].calls == ["10.99.0.5"]


def test_exclusion_que_anula_todo_se_rechaza():
    with pytest.raises(RoEError):
        parse_roe(roe_data(scope={"cidrs": ["10.99.0.0/24"], "domains": []},
                           exclusions={"hosts": ["10.99.0.0/24"], "domains": []}))


# --- Emisión por fase --------------------------------------------------------

def test_roe_valido_emite_token_de_la_fase_con_ttl(issuer, audit):
    t = issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW)
    ttl = load_policy()["phases"]["recon"]["token_ttl_minutes"] * 60
    assert t.phase is Phase.RECON
    assert t.window_start == NOW.timestamp()
    assert t.window_end == NOW.timestamp() + ttl
    assert t.excluded == ("10.99.0.1",)
    assert audit.entries[-1]["action"] == "token.issue"
    assert audit.entries[-1]["result"] == "OK"


def test_token_no_vence_despues_del_fin_de_la_ventana(issuer):
    tarde = datetime(2026, 11, 20, 20, 50, tzinfo=UTC)      # 10 min antes del fin
    t = issuer.issue(parse_roe(roe_data()), Phase.RECON, now=tarde)
    assert t.window_end == datetime(2026, 11, 20, 21, 0, tzinfo=UTC).timestamp()


def test_fase_no_autorizada_en_el_roe(issuer, audit):
    roe = parse_roe(roe_data(phases=["recon"]))
    with pytest.raises(ScopeViolation):
        issuer.issue(roe, Phase.VALIDATE, now=NOW)
    assert audit.entries[-1]["result"] == "BLOCKED"
    assert audit.entries[-1]["reason"] == "phase_not_in_roe"


def test_fuera_de_la_ventana(issuer, audit):
    with pytest.raises(ScopeViolation):
        issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW + timedelta(days=1))
    assert audit.entries[-1]["reason"] == "outside_window"


def test_token_vencido_no_se_renueva(issuer, audit, monkeypatch):
    t = issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW)
    monkeypatch.setattr(time, "time", lambda: t.window_end + 1)
    h, adapters = _harness(issuer, audit)
    emitidos = sum(e["action"] == "token.issue" for e in audit.entries)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.5", t)
    assert audit.entries[-1]["reason"] == "token_expired"
    assert sum(e["action"] == "token.issue" for e in audit.entries) == emitidos
    assert not hasattr(issuer, "renew")
    assert adapters["httpx.probe"].calls == []


# --- Integridad del token ----------------------------------------------------

def test_token_fabricado(issuer, audit):
    h, adapters = _harness(issuer, audit)
    falso = ScopeToken("lab-2026-001", ("0.0.0.0/0",), (), time.time() - 5, time.time() + 600,
                       Phase.RECON)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.5", falso)
    assert audit.entries[-1]["reason"] == "token_invalid"
    assert adapters["httpx.probe"].calls == []


def test_token_alterado(issuer, audit, monkeypatch):
    import dataclasses
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    h, _ = _harness(issuer, audit)
    t = issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW)
    alterado = dataclasses.replace(t, phase=Phase.VALIDATE)
    with pytest.raises(ScopeViolation):
        h.invoke("validation", act("poc_catalog.run_parametrized", Phase.VALIDATE),
                 "10.99.0.5", alterado)
    assert audit.entries[-1]["reason"] == "token_invalid"


def test_token_de_otro_emisor(audit, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    otro = TokenIssuer(AuditLog(), key=b"x" * 32)
    propio = TokenIssuer(audit, key=b"k" * 32)
    h, _ = _harness(propio, audit)
    t = otro.issue(parse_roe(roe_data()), Phase.RECON, now=NOW)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.5", t)
    assert audit.entries[-1]["reason"] == "token_invalid"


def test_clave_corta_se_rechaza():
    with pytest.raises(ValueError):
        TokenIssuer(AuditLog(), key=b"corta")


def test_ningun_scopetoken_fuera_del_emisor():
    culpables = []
    for path in (ROOT / "harness").rglob("*.py"):
        if path.name == "tokens.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "ScopeToken":
                culpables.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert culpables == []


# --- Revocación --------------------------------------------------------------

def test_token_vivo_despues_de_revocar(issuer, audit, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    h, adapters = _harness(issuer, audit)
    roe = parse_roe(roe_data())
    t = issuer.issue(roe, Phase.RECON, now=NOW)
    issuer.revoke(roe.engagement_id, by="Docente")
    assert any(e["action"] == "roe.revoke" and e["agent"] == "Docente" for e in audit.entries)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.5", t)
    assert audit.entries[-1]["reason"] == "token_revoked"
    with pytest.raises(ScopeViolation):
        issuer.issue(roe, Phase.RECON, now=NOW)
    assert adapters["httpx.probe"].calls == []


def test_revocacion_sobrevive_a_un_emisor_nuevo(audit):
    roe = parse_roe(roe_data())
    TokenIssuer(audit, key=b"k" * 32).revoke(roe.engagement_id, by="Docente")
    nuevo = TokenIssuer(audit, key=b"k" * 32)          # reinicio del proceso
    with pytest.raises(ScopeViolation):
        nuevo.issue(roe, Phase.RECON, now=NOW)


def test_roe_rechazado_no_toca_la_entrada():
    data = roe_data()
    original = copy.deepcopy(data)
    parse_roe(data)
    assert data == original


def test_resultado_de_emision_queda_con_fase_de_control(issuer, audit):
    issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW)
    e = audit.entries[-1]
    assert (e["phase"], e["result"]) == ("control", Result.OK.value)


def test_contacto_de_emergencia_incompleto_se_rechaza():
    with pytest.raises(RoEError) as exc:
        parse_roe(roe_data(emergency_contacts=[{"name": "Santi"}]))
    assert "emergency_contacts" in " ".join(exc.value.errors)


def test_token_sin_exclusiones_alterado(issuer, audit, monkeypatch):
    """Quitarle las exclusiones al token para llegar al host excluido: token_invalid."""
    import dataclasses
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    h, adapters = _harness(issuer, audit)
    t = dataclasses.replace(issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW), excluded=())
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.1", t)
    assert audit.entries[-1]["reason"] == "token_invalid"
    assert adapters["httpx.probe"].calls == []


# --- Hallazgos del security-reviewer -----------------------------------------

def test_roe_alterado_en_memoria_no_amplia_el_token(issuer):
    """issue() no confía en los campos del objeto: vuelve a validar la fuente."""
    import dataclasses
    trucho = dataclasses.replace(parse_roe(roe_data()), cidrs=("0.0.0.0/0",), excluded=())
    t = issuer.issue(trucho, Phase.RECON, now=NOW)
    assert t.allowed_cidrs == ("10.99.0.0/24",)
    assert t.excluded == ("10.99.0.1",)


def test_ningun_mac_ni_scopetoken_por_atributo_fuera_del_emisor():
    culpables = []
    for path in (ROOT / "harness").rglob("*.py"):
        if path.name == "tokens.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute) and node.attr in {"ScopeToken", "_mac"}:
                culpables.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert culpables == []


def test_la_clave_no_queda_en_el_entorno_ni_en_repr(monkeypatch):
    from harness.adapters.common import safe_env
    monkeypatch.setenv("PTAAS_TOKEN_KEY", "s" * 40)
    i = TokenIssuer(AuditLog())
    import os
    assert "PTAAS_TOKEN_KEY" not in os.environ
    assert "s" * 40 not in repr(i)
    monkeypatch.setenv("PTAAS_OTRA", "x")
    assert not any(k.startswith("PTAAS_") for k in safe_env())


def test_revocacion_desde_otro_emisor_con_la_misma_bitacora(audit, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    a = TokenIssuer(audit, key=b"k" * 32)
    b = TokenIssuer(audit, key=b"k" * 32)
    t = a.issue(parse_roe(roe_data()), Phase.RECON, now=NOW)
    b.revoke("lab-2026-001", by="Docente")
    assert a.verify(t) == "token_revoked"


@pytest.mark.parametrize("cambio", [{"phase": "recon"}, {"mac": "ñ" * 64}, {"mac": 123}])
def test_token_con_tipos_raros_queda_bloqueado_y_registrado(issuer, audit, monkeypatch, cambio):
    import dataclasses
    monkeypatch.setattr(time, "time", lambda: NOW.timestamp())
    h, adapters = _harness(issuer, audit)
    t = dataclasses.replace(issuer.issue(parse_roe(roe_data()), Phase.RECON, now=NOW), **cambio)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.5", t)
    assert audit.entries[-1]["reason"] == "token_invalid"
    assert adapters["httpx.probe"].calls == []


@pytest.mark.parametrize("texto", [
    "engagement_id: x\nscope: []\n",
    "engagement_id: x\nexclusions: x\nscope: {cidrs: [10.99.0.0/24]}\n",
    "engagement_id: x\nwindow: {start: '0001-01-01T00:00:00+23:00', end: '0001-01-02T00:00:00+23:00'}\n",
    "engagement_id: x\nraro: !!set {a, b}\n",
    "engagement_id: x\nraro: !!binary aGVsbG8=\n",
    ": : :\n",
])
def test_roe_malformado_da_roe_error_y_no_excepcion_cruda(texto):
    with pytest.raises(RoEError) as exc:
        parse_roe(texto)
    assert exc.value.code == "roe_invalid"


def test_exclusiones_que_cubren_todo_por_union():
    with pytest.raises(RoEError):
        parse_roe(roe_data(scope={"cidrs": ["10.99.0.0/24"], "domains": []},
                           exclusions={"hosts": ["10.99.0.0/25", "10.99.0.128/25"],
                                       "domains": []}))


# --- change 005: criticidad opcional por host ---------------------------------------------
def test_criticidad_valida_y_por_defecto():
    from harness.roe import criticality_of
    roe = parse_roe(roe_data(criticality={"DVWA.lab.test": 4, "10.99.0.20": 5}))
    assert roe.criticality == (("10.99.0.20", 5), ("dvwa.lab.test", 4))
    assert criticality_of(roe, "dvwa.lab.test") == (4, False)
    assert criticality_of(roe, "juiceshop.lab.test") == (3, True)


@pytest.mark.parametrize("value", [9, 0, "4", 4.0, True, None])
def test_criticidad_fuera_de_rango(value):
    with pytest.raises(RoEError) as exc:
        parse_roe(roe_data(criticality={"dvwa.lab.test": value}))
    assert any("criticality.dvwa.lab.test" in e for e in exc.value.errors)


@pytest.mark.parametrize("host", ["otro.lab.test", "10.98.0.5", "-x"])
def test_criticidad_de_un_host_fuera_del_alcance(host):
    with pytest.raises(RoEError) as exc:
        parse_roe(roe_data(criticality={host: 4}))
    assert any("criticality" in e for e in exc.value.errors)


def test_criticidad_que_no_es_mapa():
    with pytest.raises(RoEError):
        parse_roe(roe_data(criticality=["dvwa.lab.test"]))
