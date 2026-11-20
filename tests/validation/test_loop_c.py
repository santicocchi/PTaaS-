"""Change 006 · validation: loop C por hallazgo (D1, D2, D4, D5, D8, D9).

Todo pasa por `Harness.invoke` con un token de VALIDATE. El sandbox usa `FakeDocker`: el
`Sender` "se invoca" cuando hay un `docker run`.
"""
import html
import json
from urllib.parse import unquote

import pytest

from harness.analysis import FindingStore, Observation
from harness.approvals import ApprovalStore, QueueItem, record_decision
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase, Result
from harness.engagement import State
from harness.evidence import verify_evidence
from harness.poc.catalog import load_catalog
from harness.policy_loader import phase_allowlist
from harness.sandbox import DockerSandbox, SandboxTimeout
from harness.schemas import CandidateFinding, PrioritizedVuln
from harness.validation import CAPABILITY, ValidationLoop
from tests.conftest import TEST_ISSUER, act, engagement_in, make_token
from tests.validation.test_sandbox import IMAGE, FakeDocker, ok_response

ENG = "eng-1"
T0 = 2_000_000.0
DNS = {"dvwa.lab.test": ["10.99.0.10"], "juiceshop.lab.test": ["10.99.0.20"],
       "otro.lab.test": ["10.99.0.30"]}


def reflect(req):
    canary = unquote(req["path"].split("=", 1)[1])
    return 0, ok_response(body=f"<p>{canary}</p>")


def escaped(req):
    canary = unquote(req["path"].split("=", 1)[1])
    return 0, ok_response(body=f"<p>{html.escape(canary)}</p>")


class Lab:
    def __init__(self, tmp_path, docker=None, state=State.VALIDATE, now=T0 + 60):
        self.tmp = tmp_path
        self.docker = docker or FakeDocker()
        self.audit = AuditLog()
        self.catalog = load_catalog()
        from harness.adapters.poc_catalog_adapter import PocCatalogRun
        sandbox = DockerSandbox(ENG, self.catalog, image=IMAGE, runner=self.docker)
        self.adapter = PocCatalogRun(sandbox, self.catalog, state_dir=tmp_path,
                                     catalog_version="0.2.0")
        self.guard = Guard(phase_allowlist())
        self.harness = Harness(self.guard, self.audit, {CAPABILITY: self.adapter}, KillSwitch(),
                               TEST_ISSUER, resolver=lambda h: DNS.get(h, []))
        self.token = make_token(Phase.VALIDATE, cidrs=("10.99.0.0/24",),
                                domains=("lab.test",), engagement_id=ENG)
        self.store = FindingStore.open(ENG, tmp_path)
        self.approvals = ApprovalStore.open(ENG, tmp_path)
        self.engagement = engagement_in(state) if state != State.VALIDATE else _validate()
        self.now = now
        self.loop = ValidationLoop(self.harness, self.token, self.store,
                                   engagement=self.engagement, catalog=self.catalog,
                                   approvals=self.approvals, clock=lambda: self.now)
        self.vulns, self.candidates = [], []

    def finding(self, fid, cwe="CWE-693", host="dvwa.lab.test", status="confirmed",
                url=None):
        self.candidates.append(CandidateFinding(id=fid, asset_id=host, cwe=cwe,
                                                evidence_refs=[f"zap:1@http://{host}/"],
                                                host=host))
        self.vulns.append(PrioritizedVuln(finding_id=fid, status=status, rationale="r",
                                          priority=5.0))
        if url:
            self.store.add(Observation(host, 2, "zap", "1", cwe, url, "high", "Medium", ""))
        return fid

    def enqueue(self, fid, at=T0):
        """El hallazgo ya estaba en cola (lo puso una corrida anterior del loop)."""
        c = next(c for c in self.candidates if c.id == fid)
        choice = self.loop._choose(c)
        poc_id, params = choice if choice else (None, {})
        self.approvals.enqueue(QueueItem(fid, c.cwe, c.host, 5.0, poc_id, params, at))

    def approve(self, fid, at=T0 + 30):
        """Aprobación por el mismo camino que la CLI: registro + bitácora."""
        self.enqueue(fid)
        record_decision(self.approvals, self.audit, ENG, fid, "approved", "ana", "ok", at)

    def traffic(self):
        """Registros que no son decisiones del Reviewer."""
        return [e for e in self.audit.entries if not e["action"].startswith("hitl.")]

    def run(self):
        return self.loop.run(self.vulns, self.candidates)

    def controls(self, action):
        return [e for e in self.audit.entries if e["action"] == action]


def _validate():
    e = engagement_in(State.ANALYZE)
    e.approve("before_validate")
    e.advance()
    return e


# --- gate humano por hallazgo ---------------------------------------------------------------
def test_sin_aprobacion(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    res = lab.run()
    assert res.outcomes[fid].status == "pending_hitl"
    assert lab.docker.runs() == []
    assert lab.audit.entries[-1]["result"] == "PENDING_HITL"
    assert lab.approvals.item(fid) is not None            # quedó en la cola del Reviewer


def test_aprobacion_de_otro_hallazgo_del_mismo_host(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=lambda r: (0, ok_response(headers=()))))
    f1, f2 = lab.finding("F-1"), lab.finding("F-2", cwe="CWE-1021")
    lab.approve(f1)
    lab.enqueue(f2)
    res = lab.run()
    assert res.outcomes[f2].status == "pending_hitl"
    assert len(lab.docker.runs()) == 1                      # solo el del primero
    pending = [e for e in lab.audit.entries if e["result"] == "PENDING_HITL"]
    assert len(pending) == 1 and pending[0]["target"] == "dvwa.lab.test"


def test_aprobacion_vencida(tmp_path):
    lab = Lab(tmp_path, now=T0 + 30 + 61 * 60)
    fid = lab.finding("F-1")
    lab.approve(fid)
    res = lab.run()
    assert res.outcomes[fid].status == "pending_hitl"
    assert lab.docker.runs() == []


def test_reviewer_que_no_responde(tmp_path):
    lab = Lab(tmp_path, now=T0 + 61 * 60)
    fid = lab.finding("F-1")
    lab.enqueue(fid, at=T0)
    res = lab.run()
    assert (res.outcomes[fid].status, res.outcomes[fid].reason) == ("not_validated",
                                                                    "reviewer_timeout")
    assert lab.docker.runs() == []
    (closed,) = lab.controls("validation.closed")
    assert closed["reason"] == "reviewer_timeout" and closed["result"] == "ABORTED"
    assert lab.approvals.closure(fid).reason == "reviewer_timeout"


def test_timeout_no_cuenta_antes_de_tiempo(tmp_path):
    lab = Lab(tmp_path, now=T0 + 59 * 60)
    fid = lab.finding("F-1")
    lab.enqueue(fid, at=T0)
    assert lab.run().outcomes[fid].status == "pending_hitl"


def test_hallazgo_rechazado(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    lab.enqueue(fid)
    lab.approvals.decide(fid, "rejected", "ana", "no", T0 + 1)
    res = lab.run()
    assert (res.outcomes[fid].status, res.outcomes[fid].reason) == ("not_validated",
                                                                    "reviewer_rejected")
    assert lab.docker.runs() == []
    assert lab.controls("validation.closed")[0]["reason"] == "reviewer_rejected"


def test_cerrado_no_se_vuelve_a_procesar(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    lab.enqueue(fid)
    lab.approvals.decide(fid, "rejected", "ana", "no", T0 + 1)
    lab.run()
    n = len(lab.audit.entries)
    again = lab.run()
    assert again.outcomes[fid].reason == "reviewer_rejected"
    assert len(lab.audit.entries) == n


# --- loop C por hallazgo --------------------------------------------------------------------
def test_hallazgo_descartado(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1", status="discarded")
    lab.approve(fid)
    res = lab.run()
    assert res.outcomes[fid].status == "skipped"
    assert lab.docker.runs() == [] and lab.traffic() == []


def test_verificacion_inexistente_en_el_catalogo(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1", cwe="CWE-89")
    lab.approve(fid)
    res = lab.run()
    assert (res.outcomes[fid].status, res.outcomes[fid].reason) == ("not_validated",
                                                                    "no_catalog_entry")
    assert lab.docker.runs() == []
    assert [e["action"] for e in lab.traffic()] == ["validation.closed"]


def test_host_fuera_de_lab_targets_no_tiene_entrada(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1", host="otro.lab.test")
    lab.approve(fid)
    res = lab.run()
    assert res.outcomes[fid].reason == "no_catalog_entry" and lab.docker.runs() == []


def test_juice_shop_esta_en_lab_targets(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=lambda r: (0, ok_response(headers=()))))
    fid = lab.finding("F-1", host="juiceshop.lab.test")
    lab.approve(fid)
    assert lab.run().outcomes[fid].status == "validated"
    assert lab.docker.stdin[0]["ip"] == "10.99.0.20"


def test_positivo_en_el_primer_intento(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=reflect))
    fid = lab.finding("F-1", cwe="CWE-79", url="http://dvwa.lab.test/vulnerabilities/xss_r/?name=x")
    lab.approve(fid)
    res = lab.run()
    out = res.outcomes[fid]
    assert out.status == "validated" and out.poc_id == "POC-REFLECT-001"
    assert len(lab.docker.runs()) == 1 and out.attempts == 1
    req = lab.docker.stdin[0]
    assert req["path"].startswith("/vulnerabilities/xss_r/?name=ptaas")
    assert req["ip"] == "10.99.0.10" and req["host"] == "dvwa.lab.test"
    assert lab.approvals.closure(fid).outcome == "validated"


def test_dos_intentos_negativos(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=escaped))
    fid = lab.finding("F-1", cwe="CWE-79", url="http://dvwa.lab.test/x?q=1")
    lab.approve(fid)
    res = lab.run()
    assert res.outcomes[fid].status == "not_validated" and res.outcomes[fid].attempts == 2
    canaries = [unquote(r["path"].split("=", 1)[1]) for r in lab.docker.stdin]
    assert len(canaries) == 2 and canaries[0] != canaries[1]
    attempts = lab.controls("validation.attempt")
    assert [e["result"] for e in attempts] == ["OK", "OK"]
    assert len({e["evidence"] for e in attempts}) == 2


def test_engagement_fuera_de_validate(tmp_path):
    lab = Lab(tmp_path, state=State.ANALYZE)
    fid = lab.finding("F-1")
    lab.approve(fid)
    res = lab.run()
    assert res.reason == "engagement fuera de VALIDATE"
    assert res.outcomes == {} and lab.docker.runs() == [] and lab.traffic() == []


def test_kill_switch_activo_no_arranca(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    lab.approve(fid)
    lab.harness.kill(ENG, "operator")
    res = lab.run()
    assert res.reason == "abortado: kill switch" and lab.docker.runs() == []


def test_exige_token_validate(tmp_path):
    lab = Lab(tmp_path)
    with pytest.raises(ValueError):
        ValidationLoop(lab.harness, make_token(Phase.ANALYZE), lab.store,
                       engagement=lab.engagement, catalog=lab.catalog, approvals=lab.approvals)


def test_exige_el_adaptador_del_catalogo(tmp_path):
    lab = Lab(tmp_path)
    lab.harness.tools = {}
    with pytest.raises(ValueError):
        ValidationLoop(lab.harness, lab.token, lab.store, engagement=lab.engagement,
                       catalog=lab.catalog, approvals=lab.approvals)


def test_todo_pasa_por_el_harness_con_token_validate(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    lab.approve(fid)
    lab.run()
    oks = [e for e in lab.audit.entries if e["result"] == "OK" and e["phase"] != "control"]
    assert [(e["action"], e["phase"], e["target"]) for e in oks] == [
        (CAPABILITY, "validate", "dvwa.lab.test")]
    assert lab.guard._approvals == set()                    # la aprobación no queda cargada


def test_adaptador_sin_solicitud_preparada_no_envia(tmp_path):
    lab = Lab(tmp_path)
    lab.guard.approve(CAPABILITY, "dvwa.lab.test", engagement_id=ENG, phase=Phase.VALIDATE,
                      subject="F-9")
    out = lab.harness.invoke("x", act(CAPABILITY, Phase.VALIDATE), "dvwa.lab.test", lab.token,
                             subject="F-9")
    assert out["error"] == "adapter_error" and lab.docker.runs() == []


# --- sandbox y evidencia --------------------------------------------------------------------
def test_fin_de_la_validacion(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    lab.approve(fid)
    res = lab.run()
    assert lab.docker.alive == set()
    (attempt,) = lab.controls("validation.attempt")
    assert verify_evidence(tmp_path, attempt["evidence"])
    data = json.loads((tmp_path / attempt["evidence"].split("#")[0]).read_text())
    assert data["poc_id"] == "POC-CSP-001" and data["catalog_version"] == "0.2.0"
    assert data["sandbox_id"] == res.outcomes[fid].sandbox_ids[0]
    assert data["parameters"] == {"base_url": "http://dvwa.lab.test", "path": "/"}


def test_falla_la_verificacion(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=lambda r: (137, "")))
    fid = lab.finding("F-1")
    lab.approve(fid)
    res = lab.run()
    assert lab.docker.alive == set()
    attempts = lab.controls("validation.attempt")
    assert [(e["result"], e["reason"]) for e in attempts] == [("ABORTED", "sandbox_error")] * 2
    assert all(verify_evidence(tmp_path, e["evidence"]) for e in attempts)
    assert res.outcomes[fid].status == "failed"


def test_contenedor_que_no_termina(tmp_path):
    def hang(req):
        raise SandboxTimeout()
    lab = Lab(tmp_path, docker=FakeDocker(run=hang))
    fid = lab.finding("F-1")
    lab.approve(fid)
    lab.run()
    assert lab.docker.alive == set()
    assert lab.controls("validation.attempt")[0]["reason"] == "timeout"


def test_contenedor_que_no_se_puede_destruir(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=lambda r: (1, ""), rm_fails=True))
    f1, f2 = lab.finding("F-1"), lab.finding("F-2", cwe="CWE-1021")
    lab.approve(f1)
    lab.approve(f2)
    res = lab.run()
    assert res.reason == "sandbox.cleanup_failed"
    assert len(lab.docker.runs()) == 1                       # el segundo no se envía
    (ctrl,) = lab.controls("sandbox.cleanup_failed")
    assert ctrl["result"] == "ABORTED" and ctrl["reason"] == "sandbox_error"
    assert ctrl["target"].startswith("ptaas-sbx-")
    assert lab.approvals.closure(f2) is None                 # queda para cuando se resuelva


def test_huerfanos_se_barren_antes_del_primer_envio(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(orphans={"ptaas-sbx-viejo"}))
    fid = lab.finding("F-1")
    lab.approve(fid)
    lab.run()
    first_run = lab.docker.calls.index(lab.docker.runs()[0])
    assert ["docker", "rm", "-f", "ptaas-sbx-viejo"] in lab.docker.calls[:first_run]


# --- límites --------------------------------------------------------------------------------
def test_presupuesto_del_engagement_agotado(tmp_path):
    lab = Lab(tmp_path)
    for _ in range(20):
        lab.audit.record("v", act(CAPABILITY, Phase.VALIDATE), "dvwa.lab.test", lab.token,
                         Result.OK)
    fid = lab.finding("F-1")
    lab.approve(fid)
    res = lab.run()
    assert res.reason == "request_budget_exhausted"
    assert res.outcomes[fid].reason == "request_budget_exhausted"
    assert lab.docker.runs() == []
    assert lab.controls("validation.closed")[0]["reason"] == "request_budget_exhausted"


def test_presupuesto_se_agota_en_el_medio(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=escaped))
    for _ in range(19):
        lab.audit.record("v", act(CAPABILITY, Phase.VALIDATE), "dvwa.lab.test", lab.token,
                         Result.OK)
    fid = lab.finding("F-1", cwe="CWE-79", url="http://dvwa.lab.test/x?q=1")
    lab.approve(fid)
    res = lab.run()
    assert len(lab.docker.runs()) == 1 and res.reason == "request_budget_exhausted"


def test_tope_por_hallazgo_entre_corridas(tmp_path):
    lab = Lab(tmp_path, docker=FakeDocker(run=escaped))
    fid = lab.finding("F-1", cwe="CWE-79", url="http://dvwa.lab.test/x?q=1")
    lab.approve(fid)
    for _ in range(2):                                      # dos intentos de otra corrida
        lab.audit.record_control(ENG, "v", "validation.attempt", fid, Result.OK)
    res = lab.run()
    assert lab.docker.runs() == [] and res.outcomes[fid].status == "not_validated"


# --- lab_targets: host canónico completo contra un mapa explícito (revisión de seguridad) ----
@pytest.mark.parametrize("host,expected", [
    ("dvwa.lab.test", True), ("DVWA.lab.test.", True), ("juiceshop.lab.test", True),
    ("dvwa.evil.example", False), ("d-v-w-a.lab.test", False), ("dvwa", False),
    ("dvwa.lab.test.evil.example", False), ("xdvwa.lab.test", False),
    ("juice-shop.lab.test", False), ("", False),
])
def test_host_en_lab_targets(host, expected):
    from harness.poc.catalog import host_in_lab_targets
    assert host_in_lab_targets(host, ["dvwa", "juice-shop"]) is expected


def test_lab_target_desconocido_no_habilita_nada():
    from harness.poc.catalog import host_in_lab_targets
    assert host_in_lab_targets("dvwa.lab.test", ["dvwa.lab.test", "dv-wa"]) is False


def test_lab_target_desconocido_en_el_catalogo_se_rechaza():
    from harness.poc.catalog import InvalidCatalog, validate_entries
    base = {**load_catalog()["POC-CSP-001"], "lab_targets": ["dvwa", "evil"]}
    with pytest.raises(InvalidCatalog, match="evil"):
        validate_entries([base])


@pytest.mark.parametrize("host", ["dvwa.evil.example", "d-v-w-a.lab.test"])
def test_host_parecido_no_tiene_entrada(tmp_path, host):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1", host=host)
    lab.approve(fid)
    res = lab.run()
    assert res.outcomes[fid].reason == "no_catalog_entry" and lab.docker.runs() == []



# --- revisión B1: se envía exactamente lo que se aprobó -------------------------------------
def test_parametros_cambiados_despues_de_aprobar(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1", url="http://dvwa.lab.test/login.php")
    lab.approve(fid)
    # El loop B observa después otro endpoint del mismo CWE: la elección cambia.
    lab.store.add(Observation("dvwa.lab.test", 2, "zap", "2", "CWE-693",
                              "http://dvwa.lab.test/admin", "high", "Medium", ""))
    res = lab.run()
    assert res.outcomes[fid].status == "pending_hitl"
    assert lab.docker.runs() == []
    assert lab.approvals.status(fid, lab.now) == "pending"      # pide una decisión nueva
    record_decision(lab.approvals, lab.audit, ENG, fid, "approved", "ana", "nueva", lab.now)
    lab.run()
    (req,) = lab.docker.stdin
    assert req["path"] == "/admin"                                # la que se aprobó


def test_se_envia_la_solicitud_aprobada(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1", url="http://dvwa.lab.test:8080/login.php")
    lab.approve(fid)
    lab.run()
    (req,) = lab.docker.stdin
    approved = lab.approvals.item(fid)
    assert approved.params == {"base_url": "http://dvwa.lab.test:8080", "path": "/login.php"}
    assert (req["port"], req["path"]) == (8080, "/login.php")


# --- revisión M1: una fila del registro sin su control en la bitácora no habilita nada --------
def test_aprobacion_insertada_sin_la_cli(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    lab.enqueue(fid)
    lab.approvals.decide(fid, "approved", "ana", "ok", T0 + 30)    # sin bitácora
    res = lab.run()
    assert res.outcomes[fid].status == "pending_hitl" and lab.docker.runs() == []


def test_control_de_otro_hallazgo_no_habilita(tmp_path):
    lab = Lab(tmp_path)
    f1, f2 = lab.finding("F-1"), lab.finding("F-2", cwe="CWE-1021")
    lab.approve(f1)
    lab.enqueue(f2)
    lab.approvals.decide(f2, "approved", "ana", "ok", T0 + 30)     # F-2 sin control propio
    lab.run()
    assert len(lab.docker.runs()) == 1


# --- revisión M3: un rechazo revoca una aprobación vigente ------------------------------------
def test_aprobacion_revocada_no_envia(tmp_path):
    lab = Lab(tmp_path)
    fid = lab.finding("F-1")
    lab.approve(fid)
    record_decision(lab.approvals, lab.audit, ENG, fid, "rejected", "bob", "revocada", T0 + 40)
    res = lab.run()
    assert res.outcomes[fid].reason == "reviewer_rejected" and lab.docker.runs() == []


# --- revisión M4: la aprobación se vuelve a mirar antes de cada intento -----------------------
def test_aprobacion_que_vence_entre_intentos(tmp_path):
    holder = {}

    def negative_then_expire(req):
        holder["lab"].now = T0 + 30 + 61 * 60                     # vence durante el intento 1
        return escaped(req)
    lab = Lab(tmp_path, docker=FakeDocker(run=negative_then_expire))
    holder["lab"] = lab
    fid = lab.finding("F-1", cwe="CWE-79", url="http://dvwa.lab.test/x?q=1")
    lab.approve(fid)
    res = lab.run()
    assert len(lab.docker.runs()) == 1
    assert res.outcomes[fid].status == "pending_hitl" and res.outcomes[fid].attempts == 1
    assert lab.approvals.closure(fid) is None


def test_revocada_entre_intentos(tmp_path):
    holder = {}

    def negative_then_revoke(req):
        lab = holder["lab"]
        record_decision(lab.approvals, lab.audit, ENG, "F-1", "rejected", "bob", "basta",
                        T0 + 50)
        return escaped(req)
    lab = Lab(tmp_path, docker=FakeDocker(run=negative_then_revoke))
    holder["lab"] = lab
    fid = lab.finding("F-1", cwe="CWE-79", url="http://dvwa.lab.test/x?q=1")
    lab.approve(fid)
    res = lab.run()
    assert len(lab.docker.runs()) == 1
    assert res.outcomes[fid].reason == "reviewer_rejected"
