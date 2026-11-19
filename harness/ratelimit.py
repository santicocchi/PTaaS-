"""Limitador por objetivo para el orquestador (change 004, design.md D10).

Ventana deslizante de 1 segundo: en ningún segundo hay más de `rate` acciones sobre el mismo
objetivo. Reloj y espera inyectables para testear sin dormir.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class RateLimiter:
    def __init__(self, rate: int, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if rate < 1:
            raise ValueError("el rate limit debe ser al menos 1 por segundo")
        self.rate = rate
        self._clock, self._sleep = clock, sleep
        self._log: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def acquire(self, target: str) -> None:
        """Bloquea hasta que `target` tenga lugar en la ventana del último segundo."""
        while True:
            with self._lock:
                now = self._clock()
                log = self._log[target]
                while log and log[0] <= now - 1.0:
                    log.popleft()
                if len(log) < self.rate:
                    log.append(now)
                    return
                wait = log[0] + 1.0 - now
            self._sleep(wait)
