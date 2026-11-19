"""Change 004 · asset-discovery: el orquestador no supera el rate limit por objetivo."""
from harness.ratelimit import RateLimiter


class FakeClock:
    def __init__(self, t=100.0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, s):
        assert s > 0
        self.t += s


def test_rafaga_de_invocaciones_sobre_el_mismo_host():
    clock = FakeClock()
    limiter = RateLimiter(5, clock=clock.now, sleep=clock.sleep)
    times = []
    for _ in range(8):
        limiter.acquire("dvwa.lab.test")
        times.append(clock.t)
    assert times[:5] == [100.0] * 5
    assert all(t >= 101.0 for t in times[5:])
    for t in times:                        # en ninguna ventana de 1 s hay más de 5
        assert sum(1 for u in times if t <= u < t + 1) <= 5


def test_hosts_distintos_no_se_frenan_entre_si():
    clock = FakeClock()
    limiter = RateLimiter(5, clock=clock.now, sleep=clock.sleep)
    for i in range(5):
        limiter.acquire("dvwa.lab.test")
        limiter.acquire("juiceshop.lab.test")
    assert clock.t == 100.0


def test_limite_invalido():
    import pytest
    with pytest.raises(ValueError):
        RateLimiter(0)
