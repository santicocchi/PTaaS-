"""Change 005 · correlation: snapshots offline íntegros, fechados y sin coincidencias aproximadas."""
import json

import pytest

from harness.feeds import (
    CpeRange,
    FeedUnavailable,
    is_distro_marker,
    load_feeds,
    load_feeds_by_policy,
    parse_epss,
    parse_nvd,
    parse_version,
    policy_max_age_days,
    split_tech,
)
from tests.correlation.helpers import NOW, make_feeds


def test_snapshot_valido_se_carga(tmp_path):
    feeds = load_feeds(make_feeds(tmp_path), max_age_days=30, now=NOW)
    assert set(feeds.nvd) == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}
    assert feeds.epss == {"CVE-2099-0001": 0.42}
    assert feeds.synthetic and not feeds.stale


@pytest.mark.parametrize("name", ["nvd.json", "epss.csv", "cpe_aliases.yaml"])
def test_snapshot_alterado_queda_no_disponible(tmp_path, name):
    base = make_feeds(tmp_path)
    with open(base / name, "a") as fh:
        fh.write("\n# cambio después del manifiesto\n")
    with pytest.raises(FeedUnavailable) as exc:
        load_feeds(base, max_age_days=30, now=NOW)
    assert exc.value.reason == f"hash_mismatch:{name}"


def test_sin_manifiesto_no_hay_feed(tmp_path):
    base = make_feeds(tmp_path)
    (base / "manifest.json").unlink()
    with pytest.raises(FeedUnavailable) as exc:
        load_feeds(base, max_age_days=30, now=NOW)
    assert exc.value.reason == "missing"


@pytest.mark.parametrize("bad", ["{", '{"files": {}}', '{"files": {"nvd.json": 3}}'])
def test_manifiesto_malformado(tmp_path, bad):
    base = make_feeds(tmp_path)
    (base / "manifest.json").write_text(bad)
    with pytest.raises(FeedUnavailable):
        load_feeds(base, max_age_days=30, now=NOW)


def test_fecha_sin_zona_horaria_invalida_el_manifiesto(tmp_path):
    base = make_feeds(tmp_path)
    m = json.loads((base / "manifest.json").read_text())
    for f in m["files"].values():
        f["retrieved_at"] = "2026-11-18T12:00:00"
    (base / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(FeedUnavailable):
        load_feeds(base, max_age_days=30, now=NOW)


def test_snapshot_desactualizado(tmp_path):
    assert load_feeds(make_feeds(tmp_path, age_days=45), max_age_days=30, now=NOW).stale
    assert not load_feeds(make_feeds(tmp_path / "b", age_days=30), max_age_days=30,
                          now=NOW).stale


def test_la_antiguedad_maxima_sale_de_la_politica(tmp_path):
    assert policy_max_age_days() == 30
    assert load_feeds_by_policy(make_feeds(tmp_path, age_days=45), now=NOW).stale
    assert not load_feeds_by_policy(make_feeds(tmp_path / "b", age_days=3), now=NOW).stale


@pytest.mark.parametrize("bad", [0, -1, "30", 3.5, True, None])
def test_antiguedad_maxima_invalida_es_un_error(bad):
    with pytest.raises(ValueError):
        policy_max_age_days({"limits": {"max_feed_age_days": bad}})


def test_rango_de_versiones(tmp_path):
    feeds = load_feeds(make_feeds(tmp_path), max_age_days=30, now=NOW)
    assert [r.id for r in feeds.lookup("apache:http_server", (2, 4, 25))] == [
        "CVE-2099-0001", "CVE-2099-0002"]                 # 0003 es < 2.4.20
    assert [r.id for r in feeds.lookup("apache:http_server", (2, 4, 30))] == []
    assert [r.id for r in feeds.lookup("apache:http_server", (2, 4))] == [
        "CVE-2099-0001", "CVE-2099-0003"]                 # 2.4 = 2.4.0
    assert feeds.lookup("nginx:nginx", (2, 4, 25)) == []


@pytest.mark.parametrize(("rng", "version", "expected"), [
    (CpeRange("a:b", start_excl=(1, 0)), (1, 0), False),
    (CpeRange("a:b", start_excl=(1, 0)), (1, 0, 1), True),
    (CpeRange("a:b", end_incl=(2,)), (2, 0, 0), True),
    (CpeRange("a:b", end_incl=(2,)), (2, 0, 1), False),
    (CpeRange("a:b"), (1,), False),                    # "cualquier versión" no afirma nada
    (CpeRange("a:b", exact=(1, 2)), (1, 2, 0), True),
    (CpeRange("a:b", exact=(1, 2)), (1, 2, 1), False),
])
def test_comparacion_de_rangos(rng, version, expected):
    assert rng.matches("a:b", version) is expected


def test_otro_producto_no_coincide():
    assert not CpeRange("x:y", exact=(1, 2)).matches("a:b", (1, 2))


@pytest.mark.parametrize("raw", ["2.4.x", "", None, "v2.4", "2.4.25-1", "2..4"])
def test_version_que_no_se_entiende(raw):
    assert parse_version(raw) is None


def test_nombres_distintos_del_mismo_producto(tmp_path):
    feeds = load_feeds(make_feeds(tmp_path), max_age_days=30, now=NOW)
    assert feeds.product_of(split_tech("Apache httpd:2.4.25")[0]) == "apache:http_server"
    assert feeds.product_of(split_tech("Apache HTTP Server:2.4.25")[0]) == "apache:http_server"
    assert feeds.product_of("Apache Tomcat") is None   # parecido no alcanza


def test_cwe_sin_informacion_es_unknown_y_cvss_con_su_version(tmp_path):
    feeds = load_feeds(make_feeds(tmp_path), max_age_days=30, now=NOW)
    noinfo = feeds.nvd["CVE-2099-0002"]
    assert noinfo.cwes == () and (noinfo.cvss_score, noinfo.cvss_version) == (5.3, "3.1")
    assert feeds.nvd["CVE-2099-0001"].cvss_version == "4.0"


def test_registros_raros_se_ignoran():
    raw = json.dumps({"vulnerabilities": [
        {"cve": {"id": "no-es-cve"}},
        {"cve": {"id": "CVE-2099-0009", "metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 99}}, {"cvssData": {"baseScore": True}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": False, "criteria": "cpe:2.3:a:x:y:1.0"},
                {"vulnerable": True, "criteria": "cpe:2.3:o:x:y:1.0"},
                {"vulnerable": True, "criteria": "cpe:2.3:a:x:y:1.x"}]}]}]}}]})
    rec = parse_nvd(raw)
    assert list(rec) == ["CVE-2099-0009"]
    assert rec["CVE-2099-0009"].cvss_score is None and rec["CVE-2099-0009"].ranges == ()


def test_epss_descarta_filas_invalidas():
    raw = ("#model_version:x,score_date:y\ncve,epss,percentile\nCVE-2099-0001,0.5,0.9\n"
           "CVE-2099-0002,1.5,0.9\nbasura,0.1,0.1\nCVE-2099-0003,nan?,0\n")
    assert parse_epss(raw) == {"CVE-2099-0001": 0.5}


@pytest.mark.parametrize(("techs", "expected"), [
    (["Debian"], True), (["Apache/2.4.25 (Ubuntu)"], True),
    (["Apache HTTP Server:2.4.25", "PHP"], False)])
def test_marca_de_distribucion(techs, expected):
    assert is_distro_marker(techs) is expected


def test_el_snapshot_del_repo_es_valido_y_sintetico():
    feeds = load_feeds(max_age_days=100000)
    assert feeds.synthetic                     # hasta que el equipo genere el real (D2)
    assert all(cid.startswith("CVE-2099-") for cid in feeds.nvd)
