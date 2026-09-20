"""Tests for observability: health checks, metrics, and Prometheus export."""

from __future__ import annotations

from starlette.testclient import TestClient

from app.api.main import create_app
from app.services.observability import MetricsCollector, metrics


def test_health_endpoints() -> None:
    app = create_app()
    client = TestClient(app)

    # Liveness probe
    live_resp = client.get("/health/live")
    assert live_resp.status_code == 200
    assert live_resp.json() == {"status": "live"}

    # Readiness probe
    ready_resp = client.get("/health/ready")
    assert ready_resp.status_code == 200
    assert ready_resp.json() == {"status": "ready"}

    # Component health
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    data = health_resp.json()
    assert data["status"] == "ok"
    assert data["components"]["database"] == "ok"
    assert data["components"]["api"] == "ok"


def test_prometheus_metrics_endpoint() -> None:
    app = create_app()
    client = TestClient(app)

    # Hit health to generate some traffic
    client.get("/health")

    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    assert "text/plain" in metrics_resp.headers["content-type"]
    text = metrics_resp.text
    assert "trinetra_http_requests_total" in text


def test_metrics_collector_unit() -> None:
    collector = MetricsCollector()
    collector.inc_counter("test_counter", 1.0, env="test", service="api")
    collector.inc_counter("test_counter", 2.0, env="test", service="api")
    collector.set_gauge("test_gauge", 42.0, cluster="prod")
    collector.observe_histogram("test_hist", 0.15, endpoint="/scans")
    collector.observe_histogram("test_hist", 0.25, endpoint="/scans")

    output = collector.generate_prometheus_text()
    assert "# TYPE test_counter counter" in output
    assert 'test_counter{env="test",service="api"} 3.0' in output
    assert "# TYPE test_gauge gauge" in output
    assert 'test_gauge{cluster="prod"} 42.0' in output
    assert "# TYPE test_hist histogram" in output
    assert 'test_hist_count{endpoint="/scans"} 2' in output
    assert 'test_hist_sum{endpoint="/scans"} 0.400000' in output
