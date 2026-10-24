"""Per-subject rate limit: a sliding minute window and a rolling daily quota.

In memory, one process. Safe from threads and from async tasks (every operation
runs under one short ``threading.Lock`` and never awaits while holding it).

Memory is bounded on both axes:
  * per subject: the minute window keeps at most ``per_minute`` timestamps and the
    day window keeps at most 25 hourly counters;
  * subjects: at most ``max_subjects`` are tracked. When the table is full, idle
    subjects (nothing in the last 25 hours) are evicted first; if it is still full
    a new subject is refused (fail closed) rather than evicting someone's history,
    which would reset their quota.

Subjects are authenticated, enrolled identities, so the table stays small in
practice; the cap only matters if something upstream goes wrong.
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

_MINUTE = 60.0
_HOUR = 3600.0
# Day quota is counted over the current hour plus the previous 24 hourly buckets,
# i.e. between 24 and 25 hours of history: never more lenient than a true 24 h window.
_DAY_BUCKETS = 25


class RateLimited(Exception):
    """The caller is over a limit. ``reason`` is safe to show to the caller."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Window:
    minute: deque[float] = field(default_factory=deque)
    # (hour index, count), oldest first
    hours: deque[list[int]] = field(default_factory=deque)
    last_seen: float = 0.0


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a positive integer") from None
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


class RateLimiter:
    def __init__(
        self,
        per_minute: int = 60,
        per_day: int = 2000,
        *,
        max_subjects: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if per_minute <= 0 or per_day <= 0 or max_subjects <= 0:
            raise ValueError("rate limits must be positive")
        self.per_minute = per_minute
        self.per_day = per_day
        self.max_subjects = max_subjects
        self._clock = clock
        self._lock = threading.Lock()
        self._subjects: dict[str, _Window] = {}

    @classmethod
    def from_env(cls, *, scale: int = 1) -> RateLimiter:
        """Limits from MCP_RATE_PER_MIN / MCP_RATE_PER_DAY (defaults 60 / 2000).

        ``scale`` multiplies both, for coarser limiters layered on the same knobs.
        Invalid values raise ValueError so the process refuses to start.
        """
        per_min = _positive_int_env("MCP_RATE_PER_MIN", 60)
        per_day = _positive_int_env("MCP_RATE_PER_DAY", 2000)
        return cls(per_min * scale, per_day * scale)

    def hit(self, subject: str) -> None:
        """Count one call for ``subject``; raise RateLimited instead if over a limit.

        A refused call is not counted, so a client that backs off recovers on time.
        """
        now = self._clock()
        hour = math.floor(now / _HOUR)
        with self._lock:
            win = self._subjects.get(subject)
            if win is None:
                if len(self._subjects) >= self.max_subjects:
                    self._evict_idle(now)
                if len(self._subjects) >= self.max_subjects:
                    raise RateLimited("rate limiter is at capacity; try again later")
                win = self._subjects[subject] = _Window()

            minute = win.minute
            while minute and minute[0] <= now - _MINUTE:
                minute.popleft()
            hours = win.hours
            while hours and hours[0][0] <= hour - _DAY_BUCKETS:
                hours.popleft()

            if len(minute) >= self.per_minute:
                raise RateLimited(f"rate limit exceeded: {self.per_minute} calls per minute")
            if sum(count for _, count in hours) >= self.per_day:
                raise RateLimited(f"daily quota exceeded: {self.per_day} calls per day")

            minute.append(now)
            if hours and hours[-1][0] == hour:
                hours[-1][1] += 1
            else:
                hours.append([hour, 1])
            win.last_seen = now

    def _evict_idle(self, now: float) -> None:
        cutoff = now - _DAY_BUCKETS * _HOUR
        for subject in [s for s, w in self._subjects.items() if w.last_seen <= cutoff]:
            del self._subjects[subject]

    def __len__(self) -> int:
        with self._lock:
            return len(self._subjects)
