"""Client-side throttle: at most max_requests per rolling window (FR-8, spec 5.4)."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable


class TokenBucket:
    def __init__(
        self,
        max_requests: int,
        per_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self._clock = clock
        self._sleep = sleep
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            while True:
                now = self._clock()
                while self._times and now - self._times[0] >= self.per_seconds:
                    self._times.popleft()
                if len(self._times) < self.max_requests:
                    self._times.append(now)
                    return
                self._sleep(self._times[0] + self.per_seconds - now)
