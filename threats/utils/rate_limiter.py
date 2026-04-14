"""Token-bucket rate limiter for LLM and HTTP calls."""

import threading
import time


class RateLimiter:
    """Simple token-bucket limiter. Thread-safe."""

    def __init__(self, requests_per_minute: int) -> None:
        self._rpm = requests_per_minute
        self._interval = 60.0 / max(requests_per_minute, 1)
        self._lock = threading.Lock()
        self._last_call: float = 0.0

    def acquire(self) -> None:
        with self._lock:
            elapsed = time.monotonic() - self._last_call
            wait = self._interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
