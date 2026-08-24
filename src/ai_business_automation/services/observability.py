"""Bounded process-local metrics and local-only readiness checks."""

import threading

from ai_business_automation.models.observability import (
    LatencyMetrics,
    MetricName,
    OperationalMetricSnapshot,
    ReadinessStatus,
)
from ai_business_automation.repositories.security_audit import SecurityAuditRepository

_MAX_VALUE = (1 << 63) - 1
_MAX_DURATION_MS = 3_600_000


class OperationalMetrics:
    """Fixed counters and one aggregate keep process memory constant."""

    def __init__(self) -> None:
        self._counters = {name: 0 for name in MetricName}
        self._latency_count = 0
        self._latency_total = 0
        self._latency_minimum = _MAX_DURATION_MS
        self._latency_maximum = 0
        self._lock = threading.Lock()

    @property
    def counter_slots(self) -> int:
        return len(self._counters)

    def increment(self, name: MetricName) -> None:
        with self._lock:
            self._counters[name] = min(self._counters[name] + 1, _MAX_VALUE)

    def observe_request_latency(self, duration_ms: int) -> None:
        bounded = min(max(duration_ms, 0), _MAX_DURATION_MS)
        with self._lock:
            self._latency_count = min(self._latency_count + 1, _MAX_VALUE)
            self._latency_total = min(self._latency_total + bounded, _MAX_VALUE)
            self._latency_minimum = min(self._latency_minimum, bounded)
            self._latency_maximum = max(self._latency_maximum, bounded)

    def snapshot(self) -> OperationalMetricSnapshot:
        with self._lock:
            counters = {name.value: value for name, value in self._counters.items()}
            latency = LatencyMetrics(
                count=self._latency_count,
                total_ms=self._latency_total,
                minimum_ms=self._latency_minimum if self._latency_count else 0,
                maximum_ms=self._latency_maximum,
            )
        return OperationalMetricSnapshot(**counters, request_latency=latency)


class LocalReadinessProbe:
    """Check only the configured local persistence adapter."""

    def __init__(self, repository: SecurityAuditRepository) -> None:
        self._repository = repository

    def status(self) -> ReadinessStatus:
        return ReadinessStatus.READY if self._repository.is_ready() else ReadinessStatus.NOT_READY
