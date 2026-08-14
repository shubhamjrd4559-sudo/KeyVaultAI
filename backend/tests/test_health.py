from unittest.mock import patch

import pytest
from rest_framework.test import APIClient


@pytest.mark.django_db
@patch("apps.common.views.dependency_health", return_value={"mongodb": "ok", "redis": "ok"})
def test_health_is_ok_when_dependencies_are_available(_health):
    response = APIClient().get("/api/v1/health/")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "services": {"mongodb": "ok", "redis": "ok"}}


@pytest.mark.django_db
@patch("apps.common.views.dependency_health", return_value={"mongodb": "unavailable", "redis": "ok"})
def test_health_is_degraded_when_a_dependency_is_unavailable(_health):
    response = APIClient().get("/api/v1/health/")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["services"]["mongodb"] == "unavailable"
