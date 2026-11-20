"""Adaptadores reales del harness. El test de contrato los recorre todos y `mypy --strict`
verifica que cada clase cumpla `ToolAdapter` (por ejemplo, que `run` reciba `addresses`)."""
from __future__ import annotations

from harness.adapters.defectdojo_adapter import DefectDojoExport
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.nmap_adapter import NmapServiceScan
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.adapters.poc_catalog_adapter import PocCatalogRun
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.adapters.zap_adapter import ZapBaselineScan
from harness.contracts import ToolAdapter
from harness.correlate import CveLookup, CweMap, EpssLookup

ADAPTER_CLASSES: tuple[type[ToolAdapter], ...] = (
    SubfinderEnum, HttpxProbe, NmapServiceScan, NucleiSafeTemplates, ZapBaselineScan,
    CveLookup, EpssLookup, CweMap, PocCatalogRun, DefectDojoExport)
