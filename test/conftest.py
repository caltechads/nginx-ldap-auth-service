from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_user_manager(mocker):
    """
    Mock the UserManager methods on the class to ensure all instances are mocked.
    """
    # Create a mock user that the app expects
    mock_user = MagicMock()
    mock_user.uid = "testuser"
    mock_user.full_name = "Test User"
    mock_user.authenticate = AsyncMock(return_value=True)

    # Create a mock manager object to return
    mock_manager = MagicMock()
    mock_manager.get = AsyncMock(return_value=mock_user)
    mock_manager.authenticate = AsyncMock(return_value=True)
    mock_manager.exists = AsyncMock(return_value=True)
    mock_manager.is_authorized = AsyncMock(return_value=True)

    # Patch the methods on UserManager class
    mocker.patch(
        "nginx_ldap_auth.app.models.UserManager.authenticate",
        mock_manager.authenticate,
    )
    mocker.patch("nginx_ldap_auth.app.models.UserManager.get", mock_manager.get)
    mocker.patch("nginx_ldap_auth.app.models.UserManager.exists", mock_manager.exists)
    mocker.patch(
        "nginx_ldap_auth.app.models.UserManager.is_authorized",
        mock_manager.is_authorized,
    )
    mocker.patch("nginx_ldap_auth.app.models.UserManager.create_pool", AsyncMock())
    mocker.patch("nginx_ldap_auth.app.models.UserManager.cleanup", AsyncMock())

    # Mock the client() method to return a mock client
    mock_client = MagicMock()
    mock_client.connect = AsyncMock()
    mocker.patch(
        "nginx_ldap_auth.app.models.UserManager.client", return_value=mock_client
    )
    mock_manager.client = MagicMock(return_value=mock_client)

    return mock_manager


@pytest.fixture
def client(mock_user_manager):  # noqa: ARG001
    """
    Return a TestClient for the FastAPI app.
    """
    from nginx_ldap_auth.app.main import app

    # Use follow_redirects=False by default
    with TestClient(
        app,
        base_url="https://testserver",
        raise_server_exceptions=True,
        follow_redirects=False,
        headers={"x-proto-scheme": "https", "x-host": "testserver"},
    ) as c:
        yield c


@pytest.fixture(autouse=True)
def mock_csrf(mocker):
    """
    Mock CSRF validation for all tests.
    """
    mocker.patch("fastapi_csrf_protect.CsrfProtect.validate_csrf", AsyncMock())
    mocker.patch(
        "fastapi_csrf_protect.CsrfProtect.generate_csrf_tokens",
        return_value=("dummy_token", "dummy_signed"),
    )
    mocker.patch("fastapi_csrf_protect.CsrfProtect.set_csrf_cookie", MagicMock())
    mocker.patch("fastapi_csrf_protect.CsrfProtect.unset_csrf_cookie", MagicMock())
    return True


@pytest.fixture(autouse=True)
def mock_settings(mocker):
    """
    Mock settings to ensure consistent behavior.
    """
    from nginx_ldap_auth.app.main import settings as app_settings

    # Patch main.py settings
    mocker.patch.object(app_settings, "cookie_name", "nginxauth")
    mocker.patch.object(app_settings, "session_backend", "memory")
    mocker.patch.object(app_settings, "ldap_authorization_filter", None)
    mocker.patch.object(app_settings, "auth_realm", "Restricted")
    mocker.patch.object(app_settings, "allow_authorization_filter_header", value=True)

    # Patch forms.py settings to use the same object
    mocker.patch("nginx_ldap_auth.app.forms.settings", app_settings)

    return app_settings
