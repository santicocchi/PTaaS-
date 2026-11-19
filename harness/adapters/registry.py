"""Adaptadores reales del harness. El test de contrato los recorre todos."""
from __future__ import annotations

from harness.adapters.nmap_adapter import NmapServiceScan
from harness.adapters.nuclei_adapter import NucleiSafeTemplates

ADAPTER_CLASSES: tuple[type, ...] = (NmapServiceScan, NucleiSafeTemplates)
