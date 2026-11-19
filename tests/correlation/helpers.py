"""Ayudas de los tests de correlación: snapshots sintéticos y un grafo del laboratorio."""
from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from harness.assets import AssetGraph
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase
from harness.correlate import CveLookup, CweMap, EpssLookup
from harness.engagement import State
from harness.feeds import ALIASES_FILE, FEEDS_DIR, load_feeds
from harness.policy_loader import phase_allowlist
from tests.conftest import TEST_ISSUER, engagement_in, make_token
from tools.build_feeds import synthetic, write_manifest

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
LAB_DNS = {"dvwa.lab.test": ["10.99.0.3"], "web.lab.test": ["10.99.0.7"]}


def make_feeds(base: Path, *, age_days: int = 1) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    nvd, epss = synthetic()
    (base / "nvd.json").write_text(json.dumps(nvd))
    (base / "epss.csv").write_text(epss)
    shutil.copy(FEEDS_DIR / ALIASES_FILE, base / ALIASES_FILE)
    write_manifest(base, True, {"nvd.json": "synthetic", "epss.csv": "synthetic"})
    manifest = json.loads((base / "manifest.json").read_text())
    when = (NOW - timedelta(days=age_days)).isoformat()
    for f in manifest["files"].values():
        f["retrieved_at"] = when
    (base / "manifest.json").write_text(json.dumps(manifest))
    return base


def lab_graph(tmp_path: Path, techs: dict[str, list[tuple[str, str]]]) -> AssetGraph:
    """`techs`: host → [(tecnología, herramienta)] repartidas como en el loop A."""
    graph = AssetGraph.open("eng-1", tmp_path)
    for host, items in techs.items():
        dom = graph.add("domain", host, source_tool="roe", iteration=0)
        svc = graph.add("http_service", f"http://{host}:80", source_tool="httpx", iteration=1)
        assert dom and svc
        for tech, tool in items:
            target = svc if tool == "httpx" else dom
            graph.add_tech(target.id, tech, source_tool=tool, iteration=1)
    return graph


class Lab:
    def __init__(self, tmp_path: Path, techs, *, age_days=1, feeds_dir=None):
        self.feeds_dir = feeds_dir or make_feeds(tmp_path / "feeds", age_days=age_days)
        self.graph = lab_graph(tmp_path, techs)
        loader = lambda: load_feeds(self.feeds_dir, max_age_days=30, now=NOW)
        self.adapters = {a.name: a for a in (CveLookup(self.graph, loader),
                                             EpssLookup(self.graph, loader),
                                             CweMap(self.graph, loader))}
        self.audit = AuditLog()
        self.harness = Harness(Guard(phase_allowlist()), self.audit, self.adapters,
                               KillSwitch(), TEST_ISSUER,
                               resolver=lambda h: LAB_DNS.get(h, []))
        self.engagement = engagement_in(State.CORRELATE)
        self.token = make_token(Phase.CORRELATE, cidrs=("10.99.0.0/24",),
                                domains=("dvwa.lab.test", "web.lab.test"))


DEBIAN = [("Apache HTTP Server:2.4.25", "httpx"), ("Debian", "httpx"),
          ("Apache httpd:2.4.25", "nmap")]
CLEAN_TWO = [("Apache HTTP Server:2.4.25", "httpx"), ("Apache httpd:2.4.25", "nmap")]
