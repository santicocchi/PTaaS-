"""Change 006 · validation: sandbox efímero (D3) y sus límites (D4), sin docker real.

El runner de docker se inyecta: `FakeDocker` simula el CLI y lleva la cuenta de los
contenedores vivos. El único test con docker real está marcado `lab` y se salta sin docker.
"""
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from harness.poc.catalog import load_catalog, run_parametrized
from harness.policy_loader import load_policy
from harness.sandbox import (
    DockerSandbox,
    SandboxCleanupFailed,
    SandboxFailure,
    SandboxLimits,
    SandboxTimeout,
    load_limits,
)

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:" + "ab" * 32
IP = "10.99.0.10"
BASE = {"base_url": "http://dvwa.lab.test", "path": "/login.php"}


def ok_response(body="<html>", headers=(("Server", "Apache"),), status=200, truncated=False):
    return json.dumps({"ok": True, "status": status, "headers": [list(h) for h in headers],
                       "body": body, "truncated": truncated})


class FakeDocker:
    """Simula `docker`: ps, network inspect, run y rm -f. Nunca ejecuta nada."""

    def __init__(self, *, internal="true", orphans=(), run=None, rm_fails=False):
        self.internal, self.rm_fails = internal, rm_fails
        self.alive = set(orphans)
        self.run = run if run is not None else (lambda req: (0, ok_response()))
        self.calls = []
        self.stdin = []

    def __call__(self, argv, stdin, timeout_s):
        self.calls.append(list(argv))
        assert argv[0] == "docker"
        cmd = argv[1:3]
        if cmd == ["network", "inspect"]:
            return 0, self.internal + "\n"
        if argv[1] == "ps":
            label = next(a for a in argv if a.startswith(("label=", "name=")))
            if label.startswith("name="):
                name = label[len("name=^/"):-1]
                return 0, "".join(f"{c}\n" for c in self.alive if c == name)
            return 0, "".join(f"{c}\n" for c in sorted(self.alive))
        if argv[1] == "rm":
            if not self.rm_fails:
                self.alive.discard(argv[-1])
            return (1, "") if self.rm_fails else (0, argv[-1])
        if argv[1] == "run":
            name = argv[argv.index("--name") + 1]
            self.alive.add(name)
            self.stdin.append(json.loads(stdin))
            result = self.run(json.loads(stdin))     # puede lanzar SandboxTimeout
            if "--rm" in argv and result[0] == 0:
                self.alive.discard(name)            # --rm: al salir bien, docker lo borra
            return result
        raise AssertionError(f"comando inesperado: {argv}")

    def runs(self):
        return [c for c in self.calls if c[1] == "run"]


@pytest.fixture(scope="module")
def cat():
    return load_catalog()


def sandbox(cat, docker, limits=None):
    return DockerSandbox("eng-1", cat, image=IMAGE, runner=docker, limits=limits)


# --- opciones del contenedor ----------------------------------------------------------------
def test_opciones_del_contenedor(cat):
    docker = FakeDocker()
    sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    (argv,) = docker.runs()
    joined = " ".join(argv)
    for opt in ("--rm", "--read-only", "--security-opt no-new-privileges",
                "--cap-drop ALL", "--user 65534:65534", "--network lab_lab",
                "--memory 128m", "--pids-limit 32", "--cpus 0.5", "--tmpfs /tmp:size=1m",
                "--label ptaas.sandbox=eng-1"):
        assert opt in joined, opt
    assert argv[-1] == IMAGE
    assert "host" not in argv and "bridge" not in argv
    assert not {"-v", "--volume", "--mount", "-e", "--env", "--env-file", "--privileged",
                "-p", "--publish"} & set(argv)
    assert not any(a.startswith(("--volume=", "--mount=", "--network=", "-v=")) for a in argv)


@pytest.mark.parametrize("network", ["host", "bridge", "none", "HOST", "lab;rm", "-x"])
def test_red_no_permitida_se_rechaza(cat, network):
    with pytest.raises(ValueError):
        DockerSandbox("eng-1", cat, image=IMAGE, runner=FakeDocker(), network=network)


@pytest.mark.parametrize("image", ["ptaas-sandbox", "ptaas-sandbox:latest", "python:3.12",
                                   "sha256:xyz", "otra@sha256:" + "a" * 64])
def test_imagen_sin_digest_se_rechaza(cat, image):
    with pytest.raises(ValueError):
        DockerSandbox("eng-1", cat, image=image, runner=FakeDocker())


def test_solicitud_por_stdin_con_ip_fijada_y_host(cat):
    docker = FakeDocker()
    sandbox(cat, docker).send("POC-CSP-001", {"base_url": "http://dvwa.lab.test:8080",
                                              "path": "/x"}, IP)
    (req,) = docker.stdin
    assert req["ip"] == IP and req["port"] == 8080 and req["host"] == "dvwa.lab.test:8080"
    assert req["method"] == "GET" and req["path"] == "/x"
    assert req["timeout_s"] == 10 and req["max_bytes"] == 65536


@pytest.mark.parametrize("params", [
    {"base_url": "https://dvwa.lab.test", "path": "/"},
    {"base_url": "http://user@dvwa.lab.test", "path": "/"},
    {"base_url": "http://dvwa.lab.test", "path": "//otro.example/x"},
    {"base_url": "http://dvwa.lab.test", "path": "@otro.example"},
    {"base_url": "http://dvwa.lab.test", "path": "/a b"},
])
def test_solicitud_invalida_no_lanza_contenedor(cat, params):
    docker = FakeDocker()
    with pytest.raises(SandboxFailure) as exc:
        sandbox(cat, docker).send("POC-CSP-001", params, IP)
    assert exc.value.kind == "sandbox_error" and docker.runs() == []


def test_direccion_que_no_es_ip_no_lanza_contenedor(cat):
    docker = FakeDocker()
    with pytest.raises(SandboxFailure):
        sandbox(cat, docker).send("POC-CSP-001", BASE, "dvwa.lab.test")
    assert docker.runs() == []


# --- ciclo de vida --------------------------------------------------------------------------
def test_fin_de_la_validacion(cat):
    docker = FakeDocker()
    out = sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    assert docker.alive == set()
    assert out.sandbox_id.startswith("ptaas-sbx-")
    assert ["docker", "rm", "-f", out.sandbox_id] in docker.calls       # finally, siempre
    assert out.record.status == 200 and out.record.headers == {"Server": "Apache"}


def test_falla_la_verificacion(cat):
    docker = FakeDocker(run=lambda req: (137, ""))
    with pytest.raises(SandboxFailure) as exc:
        sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    assert exc.value.kind == "sandbox_error" and exc.value.sandbox_id
    assert docker.alive == set()
    assert ["docker", "rm", "-f", exc.value.sandbox_id] in docker.calls


@pytest.mark.parametrize("stdout", ["no es json", json.dumps({"ok": False, "error": "connect"}),
                                    json.dumps({"ok": True, "status": "x"}), "[]"])
def test_salida_invalida_del_contenedor_es_sandbox_error(cat, stdout):
    docker = FakeDocker(run=lambda req: (0, stdout))
    with pytest.raises(SandboxFailure) as exc:
        sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    assert exc.value.kind == "sandbox_error"
    assert docker.alive == set()


def test_red_del_laboratorio_no_interna(cat):
    docker = FakeDocker(internal="false")
    with pytest.raises(SandboxFailure) as exc:
        sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    assert exc.value.kind == "sandbox_error" and exc.value.detail == "network_not_internal"
    assert docker.runs() == []


def test_contenedor_que_no_se_puede_destruir(cat):
    docker = FakeDocker(run=lambda req: (1, ""), rm_fails=True)
    with pytest.raises(SandboxCleanupFailed) as exc:
        sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    assert exc.value.kind == "sandbox_error" and exc.value.sandbox_id in docker.alive


def test_huerfanos_de_una_corrida_anterior(cat):
    docker = FakeDocker(orphans={"ptaas-sbx-viejo"})
    sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    first_run = docker.calls.index(docker.runs()[0])
    assert ["docker", "rm", "-f", "ptaas-sbx-viejo"] in docker.calls[:first_run]
    assert docker.alive == set()
    ps = docker.calls[0]
    assert ps[:3] == ["docker", "ps", "-aq"] and "label=ptaas.sandbox=eng-1" in ps


def test_huerfano_que_no_se_puede_destruir_no_lanza_otro(cat):
    docker = FakeDocker(orphans={"ptaas-sbx-viejo"}, rm_fails=True)
    with pytest.raises(SandboxCleanupFailed):
        sandbox(cat, docker).send("POC-CSP-001", BASE, IP)
    assert docker.runs() == []


# --- límites --------------------------------------------------------------------------------
def test_limites_de_la_politica():
    limits = load_limits()
    assert limits == SandboxLimits(request_timeout_s=10, container_timeout_s=30,
                                   max_response_bytes=65536, max_requests_per_finding=2,
                                   max_requests_per_engagement=20)
    assert limits.max_requests_per_finding == \
        load_policy()["limits"]["max_loop_iterations"]["validation"]


@pytest.mark.parametrize("bad", [0, -1, "10", 2.5, None])
def test_limite_invalido_se_rechaza(bad):
    policy = load_policy()
    policy["sandbox"]["limits"]["container_timeout_s"] = bad
    with pytest.raises(ValueError):
        load_limits(policy)


def test_contenedor_que_no_termina(cat):
    seen = []

    def runner(argv, stdin, timeout_s):
        seen.append(timeout_s)
        return FakeDocker.__call__(docker, argv, stdin, timeout_s)

    def hang(req):
        raise SandboxTimeout()

    docker = FakeDocker(run=hang)
    with pytest.raises(SandboxFailure) as exc:
        DockerSandbox("eng-1", cat, image=IMAGE, runner=runner).send("POC-CSP-001", BASE, IP)
    assert exc.value.kind == "timeout"
    assert docker.alive == set()                      # el finally lo destruyó
    assert 30 in seen                                 # container_timeout_s al docker run


def test_respuesta_mas_grande_que_el_limite(cat):
    limits = SandboxLimits(10, 30, 1024, 2, 20)
    params = {**BASE, "param_name": "q"}

    def big(req):
        canary = req["path"].split("q=", 1)[1]
        from urllib.parse import unquote
        body = "A" * 2000 + unquote(canary)           # el canario queda después del límite
        return 0, ok_response(body=body)

    sb = sandbox(cat, FakeDocker(run=big), limits)
    bound = sb.bind(IP)
    evidence = run_parametrized(cat, "POC-REFLECT-001", params, True, bound)
    assert bound.last is not None and bound.last.truncated is True
    assert len(bound.last.record.body.encode()) <= 1024
    assert evidence.status == "not_validated"


def test_canario_en_la_query(cat):
    docker = FakeDocker()
    bound = sandbox(cat, docker).bind(IP)
    run_parametrized(cat, "POC-REFLECT-001", {**BASE, "param_name": "q"}, True, bound)
    (req,) = docker.stdin
    assert req["path"].startswith("/login.php?q=ptaas")


# --- script del sandbox (defensa en profundidad) ---------------------------------------------
def _send_module():
    spec = importlib.util.spec_from_file_location("sandbox_send", ROOT / "lab/sandbox/send.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


REQ = {"method": "GET", "path": "/", "host": "dvwa.lab.test", "ip": "10.99.0.10", "port": 80,
       "timeout_s": 10, "max_bytes": 65536}


@pytest.mark.parametrize("ip", ["1.1.1.1", "10.97.0.10", "127.0.0.1", "::1", "dvwa.lab.test"])
def test_script_rechaza_ip_fuera_del_laboratorio(ip):
    send = _send_module()
    with pytest.raises(send.RequestError):
        send.parse_request(json.dumps({**REQ, "ip": ip}), diagnostic=False)


def test_script_en_diagnostico_omite_su_lista():
    send = _send_module()
    assert send.parse_request(json.dumps({**REQ, "ip": "1.1.1.1"}), diagnostic=True)["ip"] \
        == "1.1.1.1"


@pytest.mark.parametrize("change", [{"method": "POST"}, {"path": "//x"}, {"path": "/a\r\nb"},
                                    {"port": 0}, {"max_bytes": 10**9}, {"extra": 1}])
def test_script_rechaza_solicitudes_invalidas(change):
    send = _send_module()
    with pytest.raises(send.RequestError):
        send.parse_request(json.dumps({**REQ, **change}), diagnostic=False)


def test_script_sin_red_responde_error_en_json(capsys, monkeypatch):
    send = _send_module()
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps({**REQ, "ip": "8.8.8.8"})))
    assert send.main([]) != 0
    assert json.loads(capsys.readouterr().out)["ok"] is False


# --- red real (solo en el laboratorio) ------------------------------------------------------
def _sandbox_image():
    if shutil.which("docker") is None:
        return None
    out = subprocess.run(["docker", "image", "inspect", "ptaas-sandbox", "--format", "{{.Id}}"],
                         capture_output=True, text=True, check=False)
    return out.stdout.strip() if out.returncode == 0 else None


@pytest.mark.lab
@pytest.mark.skipif(_sandbox_image() is None, reason="sin docker o sin la imagen ptaas-sandbox")
@pytest.mark.parametrize("ip,port", [("1.1.1.1", 80), ("10.97.0.10", 80)])
def test_destino_fuera_del_laboratorio(cat, ip, port):
    """D3: con el filtro del script apagado (diagnóstico), la red igual no deja salir."""
    sb = DockerSandbox("lab-egress-test", cat, image=_sandbox_image())
    name = sb.new_name()
    argv = sb.run_argv(name, diagnostic=True)
    request = json.dumps({**REQ, "ip": ip, "port": port, "timeout_s": 5})
    try:
        proc = subprocess.run(argv, input=request, capture_output=True, text=True, timeout=30,
                              check=False)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    out = json.loads(proc.stdout)
    assert out["ok"] is False and out["error"] in ("connect_error", "timeout")
