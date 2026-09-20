"""Observability: Prometheus-compatible metrics, health diagnostics, and middleware.

Tracks scan metrics, request durations, and component health without external dependencies.
"""

from __future__ import annotations

import collections
import threading
import time
from typing import Any
from collections.abc import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class MetricsCollector:
    """Thread-safe Prometheus-compatible metrics accumulator."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = collections.defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = collections.defaultdict(float)
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = collections.defaultdict(list)

    def inc_counter(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._gauges[key] = value

    def observe_histogram(self, name: str, value: float, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._histograms[key].append(value)
            # Keep bounded memory
            if len(self._histograms[key]) > 1000:
                self._histograms[key].pop(0)

    def generate_prometheus_text(self) -> str:
        """Render all collected metrics in standard Prometheus exposition format."""
        lines: list[str] = []
        with self._lock:
            # Render counters
            reported_counter_types: set[str] = set()
            for (name, labels), val in self._counters.items():
                if name not in reported_counter_types:
                    lines.append(f"# TYPE {name} counter")
                    reported_counter_types.add(name)
                lbl_str = ""
                if labels:
                    lbl_str = "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"
                lines.append(f"{name}{lbl_str} {val}")

            # Render gauges
            reported_gauge_types: set[str] = set()
            for (name, labels), val in self._gauges.items():
                if name not in reported_gauge_types:
                    lines.append(f"# TYPE {name} gauge")
                    reported_gauge_types.add(name)
                lbl_str = ""
                if labels:
                    lbl_str = "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"
                lines.append(f"{name}{lbl_str} {val}")

            # Render histograms (count and sum)
            reported_histo_types: set[str] = set()
            for (name, labels), vals in self._histograms.items():
                if name not in reported_histo_types:
                    lines.append(f"# TYPE {name} histogram")
                    reported_histo_types.add(name)
                lbl_prefix = ",".join(f'{k}="{v}"' for k, v in labels)
                prefix = f"{{{lbl_prefix}}}" if lbl_prefix else ""
                count_lbl = f"{{{lbl_prefix}}}" if lbl_prefix else ""
                lines.append(f"{name}_count{count_lbl} {len(vals)}")
                lines.append(f"{name}_sum{count_lbl} {sum(vals):.6f}")

        return "\n".join(lines) + "\n"


# Global singleton collector
metrics = MetricsCollector()


class MetricsMiddleware(BaseHTTPMiddleware):
    """Measures HTTP request duration and status counts."""

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        start_time = time.monotonic()
        path = request.url.path
        method = request.method
        try:
            response = await call_next(request)
            duration = time.monotonic() - start_time
            status_code = str(response.status_code)
            metrics.inc_counter(
                "trinetra_http_requests_total",
                method=method,
                status=status_code,
            )
            # Group path to reduce cardinality for IDs
            simplified_path = path
            if path.startswith("/api/scans/") and len(path.split("/")) > 3:
                simplified_path = "/api/scans/:id/" + "/".join(path.split("/")[4:])
            metrics.observe_histogram(
                "trinetra_request_duration_seconds",
                duration,
                method=method,
                path=simplified_path,
            )
            return response
        except Exception:
            duration = time.monotonic() - start_time
            metrics.inc_counter(
                "trinetra_http_requests_total",
                method=method,
                status="500",
            )
            raise


__all__ = [
    "MetricsCollector",
    "MetricsMiddleware",
    "metrics",
]
