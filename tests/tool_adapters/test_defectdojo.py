"""Change 007 · tool-adapters: DefectDojo por API, con una sola llamada fija (D15).

Sin instancia de DefectDojo: un servidor HTTP falso en 127.0.0.1. El conector anota a qué IP
y puerto se pidió conectar y redirige la conexión a ese servidor local.
"""
import http.client
import http.server
import json
import threading

import pytest

from harness.adapters.defectdojo_adapter import KEY_ENV, DefectDojoExport, ExportRequest
from harness.contracts import Action, Phase
from tests.reporting.helpers import DD_HOST, DD_IP, DD_PORT, DESTINATION, Lab

KEY = "k-123456"
EXPORT = Action("defectdojo.export", Phase.REPORT)


class FakeDojo:
    def __init__(self, status=201, body=b'{"test": 7}', headers=None):
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                outer.requests.append({"path": self.path, "headers": dict(self.headers),
                                       "body": self.rfile.read(length)})
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.asked = []

    def connector(self, ip, port, timeout):
        self.asked.append((ip, port))
        return http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=timeout)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def dojo():
    servers = []

    def make(**kw):
        servers.append(FakeDojo(**kw))
        return servers[-1]
    yield make
    for s in servers:
        s.close()


def _setup(tmp_path, monkeypatch, connector, key=KEY):
    if key is None:
        monkeypatch.delenv(KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(KEY_ENV, key)
    lab = Lab(tmp_path, destinations=[DESTINATION])
    lab.finding("f-1")
    rep = lab.generate()
    lab.decide_delivery()
    lab.connector = connector
    return lab, rep


def _run(lab, rep):
    adapter = DefectDojoExport(state_dir=lab.state_dir, connector=lab.connector,
                               limits=(2.0, 4096))
    adapter.stage(ExportRequest(rep.report_id, rep.ref, DD_PORT, 3))
    token = lab.issuer.issue(lab.roe, Phase.REPORT)
    return adapter.run_subject(EXPORT, DD_HOST, token, (DD_IP,), rep.report_id)


def test_llamada_armada(tmp_path, monkeypatch, dojo):
    d = dojo()
    lab, rep = _setup(tmp_path, monkeypatch, d.connector)
    out = _run(lab, rep)
    assert out["status"] == "ok" and d.asked == [(DD_IP, DD_PORT)]
    (req,) = d.requests
    assert req["path"] == "/api/v2/import-scan/"
    assert req["headers"]["Host"] == DD_HOST
    assert req["headers"]["Authorization"] == f"Token {KEY}"
    body = req["body"].decode()
    assert 'name="scan_type"\r\n\r\nGeneric Findings Import' in body
    assert 'name="close_old_findings"\r\n\r\nfalse' in body
    assert 'name="engagement"\r\n\r\n3' in body
    assert KEY not in req["path"]


def test_redireccion_de_defectdojo(tmp_path, monkeypatch, dojo):
    d = dojo(status=302, body=b"", headers={"Location": "http://203.0.113.7/"})
    lab, rep = _setup(tmp_path, monkeypatch, d.connector)
    assert _run(lab, rep) == {"tool": "defectdojo", "status": "error",
                              "error": "invalid_output"}
    assert len(d.requests) == 1                     # no se siguió


def test_informe_cambiado_entre_aprobar_y_enviar(tmp_path, monkeypatch, dojo):
    d = dojo()
    lab, rep = _setup(tmp_path, monkeypatch, d.connector)
    rep.path.write_bytes(rep.path.read_bytes().replace(b"Falta", b"Sobra"))
    out = _run(lab, rep)
    assert out["status"] == "error" and d.asked == [] and d.requests == []


def test_sin_clave(tmp_path, monkeypatch, dojo):
    d = dojo()
    lab, rep = _setup(tmp_path, monkeypatch, d.connector, key=None)
    assert _run(lab, rep)["error"] == "adapter_error" and d.asked == []


def test_clave_fuera_de_los_registros(tmp_path, monkeypatch, dojo):
    from harness.delivery import DeliveryError
    d = dojo(status=500, body=b"error con k-123456 adentro")
    lab, _rep = _setup(tmp_path, monkeypatch, d.connector)
    with pytest.raises(DeliveryError) as exc:
        lab.deliver()
    assert KEY not in str(exc.value)
    assert KEY not in json.dumps(lab.audit.entries)
    for path in lab.state_dir.rglob("*"):
        if path.is_file() and path.suffix == ".json":
            assert KEY not in path.read_text(), path


def test_defectdojo_caido(tmp_path, monkeypatch):
    def refused(ip, port, timeout):
        return http.client.HTTPConnection("127.0.0.1", 1, timeout=timeout)   # nadie escucha
    lab, rep = _setup(tmp_path, monkeypatch, refused)
    assert _run(lab, rep) == {"tool": "defectdojo", "status": "error", "error": "exec_error"}


def test_respuesta_de_error(tmp_path, monkeypatch, dojo):
    d = dojo(status=500, body=b'{"detail": "boom"}')
    lab, rep = _setup(tmp_path, monkeypatch, d.connector)
    assert _run(lab, rep)["error"] == "invalid_output"


@pytest.mark.parametrize("body", [b"no es json", b'{"sin": "test"}', b"x" * 5000],
                         ids=["no-json", "sin-test", "grande"])
def test_respuesta_rara(tmp_path, monkeypatch, dojo, body):
    d = dojo(status=201, body=body)
    lab, rep = _setup(tmp_path, monkeypatch, d.connector)
    assert _run(lab, rep)["error"] == "invalid_output"


def test_timeout(tmp_path, monkeypatch):
    class Slow(http.client.HTTPConnection):
        """Conecta y envía sin red; la respuesta no llega a tiempo."""
        def connect(self):
            pass

        def send(self, data):
            pass

        def getresponse(self):
            raise TimeoutError

    lab, rep = _setup(tmp_path, monkeypatch, lambda ip, port, t: Slow("127.0.0.1", 1))
    assert _run(lab, rep)["error"] == "timeout"


def test_envio_exitoso(tmp_path, monkeypatch, dojo):
    d = dojo(status=201, body=b'{"test": 7}')
    lab, rep = _setup(tmp_path, monkeypatch, d.connector)
    out = _run(lab, rep)
    assert out["evidence"].startswith("reports/eng-1/export-report-v1.json#sha256=")
    summary = json.loads((lab.state_dir / out["evidence"].split("#")[0]).read_bytes())
    assert summary["http_status"] == 201 and summary["test_id"] == 7
    sent = d.requests[0]["body"]
    start = sent.index(b'filename="report-v1.json"')
    payload = sent[sent.index(b"\r\n\r\n", start) + 4:sent.rindex(b"\r\n--ptaas-")]
    import hashlib
    assert summary["document_sha256"] == hashlib.sha256(payload).hexdigest()
    assert KEY not in json.dumps(summary)


def test_entrega_por_api_de_punta_a_punta(tmp_path, monkeypatch, dojo):
    from harness.engagement import State
    d = dojo(status=201, body=b'{"test": 7}')
    lab, rep = _setup(tmp_path, monkeypatch, d.connector)
    h = lab.harness()
    result = lab.deliver(h)
    assert result.mode == "api" and lab.engagement.state == State.DELIVERED
    assert d.asked == [(DD_IP, DD_PORT)] and len(d.requests) == 1
    (done,) = lab.control("report.delivered")
    assert (done["target"], done["subject"]) == ("api", "report-v1")
    receipt = json.loads((lab.state_dir / result.receipt.split("#")[0]).read_bytes())
    assert receipt["report_sha256"] == rep.ref.split("=", 1)[1]
    assert receipt["export"].startswith("reports/eng-1/export-report-v1.json#sha256=")
    sent = [(e["result"], e["phase"], e["target"]) for e in lab.audit.entries
            if e["action"] == "defectdojo.export"]
    assert sent == [("OK", "report", DD_HOST)]
    assert h.guard._approvals == set()                      # la aprobación se retiró
