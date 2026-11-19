"""Emisor de scope tokens (change 003). Única ruta autorizada para crear un ScopeToken.

Los tokens llevan un HMAC-SHA256 del emisor. La clave sale de PTAAS_TOKEN_KEY (≥ 32 bytes)
o se genera al azar al arrancar; nunca se escribe en código, logs ni bitácora.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime

from harness.contracts import (
    AuditSink,
    Phase,
    Resolver,
    Result,
    ScopeToken,
    ScopeViolation,
    _is_ip,
    normalize_target,
    system_resolver,
)
from harness.policy_loader import load_policy
from harness.roe import RoE, parse_roe

ISSUE_ACTION = "token.issue"
REVOKE_ACTION = "roe.revoke"
MIN_KEY_BYTES = 32


def _payload(token: ScopeToken) -> bytes:
    fields = dataclasses.asdict(token)
    fields.pop("mac")
    fields["phase"] = token.phase.value
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


class TokenIssuer:
    def __init__(self, audit: AuditSink, key: bytes | None = None,
                 policy: dict | None = None,  # type: ignore[type-arg]
                 resolver: Resolver = system_resolver) -> None:
        if key is None:
            # Se saca del entorno para que no la hereden los procesos hijos (nmap, nuclei…).
            env = os.environ.pop("PTAAS_TOKEN_KEY", None)
            key = env.encode() if env else secrets.token_bytes(MIN_KEY_BYTES)
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"la clave del emisor debe tener al menos {MIN_KEY_BYTES} bytes")
        self.__key = key
        self._audit = audit
        self._policy = policy or load_policy()
        self._resolver = resolver

    def __repr__(self) -> str:                # que la clave nunca aparezca en un log
        return "TokenIssuer(<clave oculta>)"

    def _mac(self, token: ScopeToken) -> str:
        return hmac.new(self.__key, _payload(token), hashlib.sha256).hexdigest()

    def _log(self, engagement_id: str, agent: str, action: str, target: str,
             result: Result, reason: str | None = None) -> None:
        self._audit.record_control(engagement_id, agent, action, target, result, reason)

    def _revoked(self, engagement_id: str) -> bool:
        """Se lee de la bitácora cada vez: vale entre emisores y entre reinicios."""
        return engagement_id in self._audit.control_engagements(REVOKE_ACTION)

    def _reject(self, roe: RoE, phase: Phase, agent: str, reason: str) -> ScopeViolation:
        self._log(roe.engagement_id, agent, ISSUE_ACTION, phase.value, Result.BLOCKED, reason)
        return ScopeViolation(f"emisión de token {phase.value} rechazada: {reason}", reason)

    def issue(self, roe: RoE, phase: Phase, now: datetime | None = None,
              agent: str = "scope-guard") -> ScopeToken:
        ts = (now or datetime.now().astimezone()).timestamp()
        # No se confía en los campos del objeto RoE: se vuelve a validar su fuente.
        roe = parse_roe(roe.source)
        if self._revoked(roe.engagement_id):
            raise self._reject(roe, phase, agent, "token_revoked")
        if phase not in roe.phases:
            raise self._reject(roe, phase, agent, "phase_not_in_roe")
        if not roe.window_start.timestamp() <= ts < roe.window_end.timestamp():
            raise self._reject(roe, phase, agent, "outside_window")
        ttl = self._policy["phases"][phase.value]["token_ttl_minutes"] * 60
        unsigned = ScopeToken(roe.engagement_id, roe.cidrs, roe.domains, ts,
                              min(ts + ttl, roe.window_end.timestamp()), phase,
                              excluded=self._pin_excluded(roe.excluded))
        token = dataclasses.replace(unsigned, mac=self._mac(unsigned))
        self._log(roe.engagement_id, agent, ISSUE_ACTION, phase.value, Result.OK)
        return token

    def _pin_excluded(self, excluded: tuple[str, ...]) -> tuple[str, ...]:
        """Suma al token las IP de cada nombre excluido (004, security-reviewer #1).

        Si no, un host excluido por nombre se alcanzaba por su IP o por otro nombre que
        resolviera a la misma IP. Las IP quedan fijadas al emitir y firmadas en el MAC.
        """
        pinned: list[str] = list(excluded)
        for name in excluded:
            if _is_ip(name) or "/" in name:
                continue
            try:
                ips = self._resolver(name)
            except Exception:  # noqa: BLE001 - si no resuelve, queda la exclusión por nombre
                ips = []
            for raw in ips:
                ip = normalize_target(str(raw))
                if ip is not None and _is_ip(ip) and ip not in pinned:
                    pinned.append(ip)
        return tuple(pinned)

    def verify(self, token: ScopeToken) -> str | None:
        """None si el token es auténtico y no fue revocado; si no, el motivo.

        Cualquier rareza (tipos inesperados, MAC no ASCII) es `token_invalid`: falla cerrado
        y el Harness lo registra como BLOCKED.
        """
        try:
            if not isinstance(token, ScopeToken) or not isinstance(token.phase, Phase):
                return "token_invalid"
            if not hmac.compare_digest(token.mac, self._mac(token)):
                return "token_invalid"
        except (TypeError, ValueError, AttributeError):
            return "token_invalid"
        if self._revoked(token.engagement_id):
            return "token_revoked"
        return None

    def revoke(self, engagement_id: str, by: str) -> None:
        self._log(engagement_id, by, REVOKE_ACTION, engagement_id, Result.ABORTED)
