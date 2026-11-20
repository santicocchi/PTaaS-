"""Change 010 · poc-catalog: `phantomcorp` como objetivo del catálogo inerte."""
from pathlib import Path

import pytest
import yaml

from harness.poc.catalog import (
    LAB_TARGET_HOSTS,
    InvalidCatalog,
    catalog_version,
    host_in_lab_targets,
    validate_entries,
)
from tests.validation.test_loop_c import DNS, Lab
from tests.validation.test_sandbox import FakeDocker, ok_response

CATALOG = Path(__file__).resolve().parents[2] / "harness" / "poc" / "catalog.yaml"


def test_mapa_explicito_a_un_solo_fqdn():
    assert LAB_TARGET_HOSTS["phantomcorp"] == frozenset({"phantomcorp.lab.test"})


def test_todas_las_entradas_suman_phantomcorp_y_siguen_inertes():
    raw = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["entries"]
    assert catalog_version() == "0.3.0" and len(raw) == 6
    for e in raw:
        assert e["lab_targets"] == ["dvwa", "juice-shop", "phantomcorp"], e["id"]
        assert e["kind"] == "inert_check" and e["lab_only"] is True, e["id"]
        assert e["version"] == "1.1.0", e["id"]


def test_verificacion_inerte_sobre_phantomcorp_se_acepta(tmp_path, monkeypatch):
    monkeypatch.setitem(DNS, "phantomcorp.lab.test", ["10.99.0.12"])
    lab = Lab(tmp_path, docker=FakeDocker(run=lambda r: (0, ok_response(headers=()))))
    fid = lab.finding("F-1", host="phantomcorp.lab.test")
    lab.approve(fid)
    assert lab.run().outcomes[fid].status == "validated"
    assert lab.docker.stdin[0]["ip"] == "10.99.0.12"


def test_entrada_sin_phantomcorp_no_se_ejecuta(tmp_path, monkeypatch):
    monkeypatch.setitem(DNS, "phantomcorp.lab.test", ["10.99.0.12"])
    lab = Lab(tmp_path)
    for e in lab.catalog.values():
        e["lab_targets"] = ["dvwa"]
    fid = lab.finding("F-1", host="phantomcorp.lab.test")
    lab.approve(fid)
    res = lab.run()
    assert res.outcomes[fid].reason == "no_catalog_entry" and lab.docker.runs() == []


@pytest.mark.parametrize("host,expected", [
    ("phantomcorp.lab.test", True),
    ("PHANTOMCORP.lab.test.", True),
    ("phantomcorp", False),
    ("phantomcorp.lab.test.evil.test", False),
    ("x.phantomcorp.lab.test", False),
])
def test_host_parecido(host, expected):
    assert host_in_lab_targets(host, ["phantomcorp"]) is expected


def _raw_entry():
    """Entrada leída del YAML sin validar (así el test no depende de que esté firmado)."""
    raw = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["entries"][0]
    return {**raw, "approved_at": "2026-11-20"}


def test_cambio_de_catalogo_autoaprobado_se_rechaza():
    entry = {**_raw_entry(), "approved_by": "claude"}
    with pytest.raises(InvalidCatalog, match="nadie aprueba"):
        validate_entries([entry])


def test_cambio_de_catalogo_sin_firma_se_rechaza():
    entry = {**_raw_entry(), "approved_by": ""}
    with pytest.raises(InvalidCatalog, match="sin aprobación registrada"):
        validate_entries([entry])
