"""Change 006 · authorization: la aprobación humana queda atada a un hallazgo (`subject`)."""
import pytest

from harness.contracts import Action, Phase, ScopeViolation
from tests.conftest import make_token

POC = "poc_catalog.run_parametrized"


def _token():
    return make_token(phase=Phase.VALIDATE, domains=("dvwa.lab.test",))


def _action(flag=True):
    return Action(POC, Phase.VALIDATE, requires_human_approval=flag)


def _approve(guard, subject, target="dvwa.lab.test"):
    guard.approve(POC, target, engagement_id="eng-1", phase=Phase.VALIDATE, subject=subject)


@pytest.mark.parametrize("flag", [True, False])
def test_validacion_sin_sujeto(env, flag):
    h, guard, audit, _, adapters = env
    _approve(guard, "F-1")
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("validation", _action(flag), "dvwa.lab.test", _token())
    assert exc.value.reason == "missing_subject"
    assert audit.entries[-1]["result"] == "BLOCKED"
    assert audit.entries[-1]["reason"] == "missing_subject"
    assert adapters[POC].calls == []


def test_sujeto_distinto(env):
    h, guard, audit, _, adapters = env
    _approve(guard, "F-1")
    out = h.invoke("validation", _action(), "dvwa.lab.test", _token(), subject="F-2")
    assert out["status"] == "PENDING_HITL"
    assert audit.entries[-1]["result"] == "PENDING_HITL"
    assert adapters[POC].calls == []


def test_sujeto_aprobado(env):
    h, guard, audit, _, adapters = env
    _approve(guard, "F-1")
    out = h.invoke("validation", _action(), "dvwa.lab.test", _token(), subject="F-1")
    assert out["ok"] and adapters[POC].calls == ["dvwa.lab.test"]
    assert audit.entries[-1]["result"] == "OK"


def test_aprobacion_de_un_sujeto_en_otro_host_no_habilita(env):
    h, guard, _, _, adapters = env
    _approve(guard, "F-1", target="10.0.0.5")
    out = h.invoke("validation", _action(), "dvwa.lab.test", _token(), subject="F-1")
    assert out["status"] == "PENDING_HITL" and adapters[POC].calls == []


def test_aprobacion_retirada_deja_de_valer(env):
    h, guard, _, _, adapters = env
    _approve(guard, "F-1")
    guard.withdraw(POC, "dvwa.lab.test", engagement_id="eng-1", phase=Phase.VALIDATE,
                   subject="F-1")
    out = h.invoke("validation", _action(), "dvwa.lab.test", _token(), subject="F-1")
    assert out["status"] == "PENDING_HITL" and adapters[POC].calls == []


@pytest.mark.parametrize("subject", ["", " ", "F 1", "a/b", "x" * 200])
def test_sujeto_invalido_no_se_aprueba(env, subject):
    _, guard, *_ = env
    with pytest.raises(ValueError):
        _approve(guard, subject)


def test_accion_sin_gate_ignora_el_sujeto(env, token):
    h, _, audit, *_ = env
    out = h.invoke("recon", Action("httpx.probe", Phase.RECON), "10.0.0.5", token, subject="F-1")
    assert out["ok"] and audit.entries[-1]["result"] == "OK"


# --- revisión M2: el subject queda en los registros de invoke --------------------------------
def test_subject_en_los_registros_de_invoke(env):
    h, guard, audit, *_ = env
    h.invoke("validation", _action(), "dvwa.lab.test", _token(), subject="F-2")
    assert audit.entries[-1]["result"] == "PENDING_HITL" and audit.entries[-1]["subject"] == "F-2"
    _approve(guard, "F-1")
    h.invoke("validation", _action(), "dvwa.lab.test", _token(), subject="F-1")
    assert audit.entries[-1]["result"] == "OK" and audit.entries[-1]["subject"] == "F-1"


def test_missing_subject_sin_subject_en_el_registro(env):
    h, _, audit, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("validation", _action(), "dvwa.lab.test", _token())
    assert audit.entries[-1]["reason"] == "missing_subject" and "subject" not in audit.entries[-1]


# --- subject malformado: se bloquea y queda en bitácora antes de todo lo demás ---------------
@pytest.mark.parametrize("subject", ["F-1\nX", "F-1\n", "x" * 500, "", "a/../b", "F 1"])
@pytest.mark.parametrize("phase", ["validate", "recon", "killed"])
def test_subject_malformado(env, token, subject, phase):
    h, guard, audit, ks, adapters = env
    _approve(guard, "F-1")
    if phase == "killed":
        ks.engage("eng-1")
    name, tok = ((POC, _token()) if phase != "recon" else ("httpx.probe", token))
    action = _action() if phase != "recon" else Action(name, Phase.RECON)
    before = len(audit.entries)
    with pytest.raises(ScopeViolation) as exc:
        h.invoke("validation", action, "dvwa.lab.test", tok, subject=subject)
    assert exc.value.reason == "invalid_subject"
    new = audit.entries[before:]
    assert [(e["result"], e["reason"]) for e in new] == [("BLOCKED", "invalid_subject")]
    assert "subject" not in new[0]
    assert adapters[name].calls == []
    audit.verify_integrity()
