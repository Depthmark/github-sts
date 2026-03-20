"""
Tests for health and readiness probe endpoints.

Validates that:
- /health (liveness) always returns 200 regardless of readiness state
- /ready (readiness) returns 503 before startup completes
- /ready (readiness) returns 200 after startup completes
- The pygithubsts_ready metric reflects readiness state

Run with: pytest tests/test_health.py
"""

# Build a minimal FastAPI app with just the health router for isolated testing.
from fastapi import FastAPI
from starlette.datastructures import State
from starlette.testclient import TestClient

from github_sts import metrics
from github_sts.routes.health import router

_test_app = FastAPI()
_test_app.include_router(router)


class TestHealthEndpoint:
    """Liveness probe /health should always return 200."""

    def test_health_returns_ok(self):
        """Intention: /health returns 200 regardless of app.state.ready.

        What is being tested:
        - GET /health always returns {"status": "ok"} with HTTP 200.

        Expected output:
        - status_code == 200, body == {"status": "ok"}
        """
        client = TestClient(_test_app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_health_returns_ok_when_not_ready(self):
        """Intention: /health stays 200 even when readiness gate is False.

        What is being tested:
        - GET /health returns 200 with app.state.ready = False.
        """
        _test_app.state.ready = False
        client = TestClient(_test_app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestReadinessEndpoint:
    """/ready should reflect the readiness gate in app.state."""

    def test_ready_returns_503_when_not_ready(self):
        """Intention: /ready returns 503 before startup completes.

        What is being tested:
        - GET /ready returns {"ready": false} with HTTP 503 when
          app.state.ready is False.

        Expected output:
        - status_code == 503, body == {"ready": false}
        """
        _test_app.state.ready = False
        client = TestClient(_test_app)
        resp = client.get("/ready")
        assert resp.status_code == 503
        assert resp.json() == {"ready": False}

    def test_ready_returns_200_when_ready(self):
        """Intention: /ready returns 200 after startup completes.

        What is being tested:
        - GET /ready returns {"ready": true} with HTTP 200 when
          app.state.ready is True.

        Expected output:
        - status_code == 200, body == {"ready": true}
        """
        _test_app.state.ready = True
        client = TestClient(_test_app)
        resp = client.get("/ready")
        assert resp.status_code == 200
        assert resp.json() == {"ready": True}

    def test_ready_returns_503_when_state_missing(self):
        """Intention: /ready returns 503 when app.state has no ready attr.

        What is being tested:
        - GET /ready returns 503 if app.state.ready was never set
          (e.g. during very early startup before lifespan runs).

        Expected output:
        - status_code == 503, body == {"ready": false}
        """
        # Replace state with a fresh State object (no ready attribute)
        _test_app.state = State()
        client = TestClient(_test_app)
        resp = client.get("/ready")
        assert resp.status_code == 503
        assert resp.json() == {"ready": False}


class TestReadinessMetric:
    """The pygithubsts_ready metric should be settable and reflect state."""

    def test_ready_metric_exists(self):
        """Intention: verify the READY gauge metric is registered.

        What is being tested:
        - metrics.READY is a Prometheus Gauge that can be set/read.
        """
        metrics.READY.set(1)
        assert metrics.READY._value.get() == 1.0

        metrics.READY.set(0)
        assert metrics.READY._value.get() == 0.0
