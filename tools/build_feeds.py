#!/usr/bin/env python3
"""Genera los snapshots offline de `data/feeds/` (change 005, D2).

Lo corre UNA PERSONA, con internet y fuera de los tests. Nada del harness llama a esto.

    # snapshot real: baja de NVD los CVE de cada producto:versión y su EPSS de FIRST
    python tools/build_feeds.py --cpe apache:http_server:2.4.25 --cpe php:php:7.0.30

    # snapshot sintético para la demo y los tests (identificadores CVE-2099-…)
    python tools/build_feeds.py --synthetic

    # solo recalcular el manifiesto (después de editar cpe_aliases.yaml)
    python tools/build_feeds.py --manifest-only

Los archivos resultantes se suben en un PR, como cualquier otro cambio revisado.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness.feeds import (
    ALIASES_FILE,
    EPSS_FILE,
    FEEDS_DIR,
    MANIFEST_FILE,
    NVD_FILE,
    parse_epss,
    parse_nvd,
)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"


def _get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "ptaas-build-feeds"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def fetch_nvd(cpes: list[str]) -> dict[str, Any]:
    vulns: dict[str, Any] = {}
    for spec in cpes:
        vendor, product, version = spec.split(":")
        match = f"cpe:2.3:a:{vendor}:{product}:{version}"
        url = f"{NVD_API}?{urllib.parse.urlencode({'virtualMatchString': match})}"
        for item in _get_json(url).get("vulnerabilities", []):
            vulns[item["cve"]["id"]] = item
        time.sleep(6)                        # NVD sin API key: 5 pedidos cada 30 s
    return {"format": "NVD_CVE", "version": "2.0",
            "vulnerabilities": [vulns[k] for k in sorted(vulns)]}


def fetch_epss(cve_ids: list[str]) -> str:
    rows, date = [], ""
    for i in range(0, len(cve_ids), 100):
        data = _get_json(f"{EPSS_API}?{urllib.parse.urlencode({'cve': ','.join(cve_ids[i:i + 100])})}")
        for d in data.get("data", []):
            rows.append(f"{d['cve']},{d['epss']},{d['percentile']}")
            date = d.get("date", date)
    return f"#model_version:first-api,score_date:{date}\ncve,epss,percentile\n" + "\n".join(rows) + "\n"


def synthetic() -> tuple[dict[str, Any], str]:
    """Datos de PRUEBA para la demo: identificadores imposibles, nunca CVE reales."""
    def item(cid: str, cwe: str, metric: dict[str, Any], cpe: dict[str, Any]) -> dict[str, Any]:
        return {"cve": {"id": cid, "metrics": metric,
                        "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
                        "configurations": [{"nodes": [{"cpeMatch": [
                            {"vulnerable": True, **cpe}]}]}]}}

    v40 = {"cvssMetricV40": [{"type": "Primary", "cvssData": {"baseScore": 8.7}}]}
    v31 = {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 5.3}}]}
    nvd = {"format": "NVD_CVE", "version": "2.0", "synthetic": True, "vulnerabilities": [
        item("CVE-2099-0001", "CWE-22", v40,
             {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
              "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.30"}),
        item("CVE-2099-0002", "NVD-CWE-noinfo", v31,
             {"criteria": "cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*"}),
        item("CVE-2099-0003", "CWE-79", v31,
             {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
              "versionEndExcluding": "2.4.20"}),
    ]}
    epss = "#model_version:synthetic,score_date:2026-11-19\ncve,epss,percentile\n" \
           "CVE-2099-0001,0.42,0.97\n"
    return nvd, epss


def write_manifest(base: Path, synthetic_flag: bool, sources: dict[str, str]) -> None:
    now = datetime.now(UTC).isoformat(timespec="seconds")
    previous: dict[str, Any] = {}
    if (base / MANIFEST_FILE).exists():
        previous = json.loads((base / MANIFEST_FILE).read_text(encoding="utf-8"))
    files = {}
    for name in (NVD_FILE, EPSS_FILE, ALIASES_FILE):
        data = (base / name).read_bytes()
        old = previous.get("files", {}).get(name, {})
        records = (len(parse_nvd(data.decode())) if name == NVD_FILE else
                   len(parse_epss(data.decode())) if name == EPSS_FILE else None)
        files[name] = {"source": sources.get(name, old.get("source", "local")),
                       "retrieved_at": now if name in sources else old.get("retrieved_at", now),
                       "records": records, "sha256": hashlib.sha256(data).hexdigest()}
    manifest = {"synthetic": synthetic_flag, "files": files}
    (base / MANIFEST_FILE).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--cpe", action="append", default=[], help="vendor:product:version")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--manifest-only", action="store_true")
    ap.add_argument("--out", type=Path, default=FEEDS_DIR)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    if args.manifest_only:
        old = json.loads((args.out / MANIFEST_FILE).read_text(encoding="utf-8"))
        write_manifest(args.out, bool(old.get("synthetic")), {})
        return 0
    if args.synthetic:
        nvd, epss = synthetic()
        sources = {NVD_FILE: "synthetic", EPSS_FILE: "synthetic"}
    elif args.cpe:
        nvd = fetch_nvd(args.cpe)
        epss = fetch_epss([v["cve"]["id"] for v in nvd["vulnerabilities"]])
        sources = {NVD_FILE: NVD_API, EPSS_FILE: EPSS_API}
    else:
        ap.error("indicá --cpe, --synthetic o --manifest-only")
    (args.out / NVD_FILE).write_text(json.dumps(nvd, indent=1) + "\n", encoding="utf-8")
    (args.out / EPSS_FILE).write_text(epss, encoding="utf-8")
    write_manifest(args.out, args.synthetic, sources)
    print(f"snapshot escrito en {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
