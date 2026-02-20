import os
from unittest.mock import AsyncMock, MagicMock, patch

from nginx_ldap_auth.settings import Settings


def test_settings_default():
    """
    Test that settings have expected defaults.
    """
    # Required settings are provided by pytest-env in pyproject.toml
    settings = Settings()
    assert settings.cookie_name == "nginxauth"
    assert settings.session_backend == "memory"
    assert settings.ldap_starttls is True
    assert settings.insecure is False


def test_settings_env_override():
    """
    Test that environment variables override defaults.
    """
    with patch.dict(
        os.environ,
        {
            "COOKIE_NAME": "custom_cookie",
            "SESSION_BACKEND": "redis",
            "REDIS_URL": "redis://localhost:6379/0",
            "INSECURE": "True",
        },
    ):
        settings = Settings()
        assert settings.cookie_name == "custom_cookie"
        assert settings.session_backend == "redis"
        assert str(settings.redis_url) == "redis://localhost:6379/0"
        assert settings.insecure is True


def test_status_endpoint(client, mock_user_manager):
    """
    Test the /status endpoint.
    """
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "Auth service is running"}


def test_status_ldap_endpoint_success(client, mocker, mock_user_manager):
    """
    Test the /status/ldap endpoint when LDAP is working.
    """
    response = client.get("/status/ldap")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "LDAP connection successful"}


def test_status_ldap_endpoint_failure(client, mocker):
    """
    Test the /status/ldap endpoint when LDAP fails.
    """
    from bonsai import LDAPError

    # We need to reach into the UserManager.client() return value
    mock_client = MagicMock()
    mock_client.connect = AsyncMock(side_effect=LDAPError("Connection failed"))
    mocker.patch(
        "nginx_ldap_auth.app.models.UserManager.client", return_value=mock_client
    )

    response = client.get("/status/ldap")
    assert response.status_code == 500
    assert response.json() == {"status": "error", "message": "LDAP connection failed"}
