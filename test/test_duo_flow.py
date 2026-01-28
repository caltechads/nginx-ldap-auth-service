import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status


@pytest.fixture
def mock_duo_settings(mock_settings, mocker):
    """
    Mock Duo settings to enable Duo MFA.
    """
    mocker.patch.object(mock_settings, "duo_enabled", True)  # noqa: FBT003
    mocker.patch.object(mock_settings, "duo_host", "api-12345678.duosecurity.com")
    mocker.patch.object(mock_settings, "duo_ikey", "DIXXXXXXXXXXXXXXXXXX")
    mocker.patch.object(
        mock_settings, "duo_skey", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    )
    return mock_settings


@pytest.fixture
def mock_duo_client(mocker):
    """
    Mock the Duo Universal Client.
    """
    mock_client = MagicMock()
    mock_client.generate_state.return_value = "test_state"
    mock_client.create_auth_url.return_value = (
        "https://api-12345678.duosecurity.com/frame/prompt?sid=123"
    )
    mock_client.health_check.return_value = {"stat": "OK"}

    mocker.patch("duo_universal.Client", return_value=mock_client)
    return mock_client


@pytest.fixture
def redis_store(mock_settings, mocker):
    """
    Mock RedisStore to verify persistence logic without a real Redis server.
    """
    data_store = {}

    mock_store = MagicMock()

    async def mock_read(session_id, **kwargs):
        data = data_store.get(session_id)
        if data is None:
            return b""
        if isinstance(data, dict):
            return json.dumps(data).encode()
        return data

    async def mock_write(session_id, data, **kwargs):
        # data is already bytes from serializer.serialize()
        data_store[session_id] = data
        return session_id

    async def mock_remove(session_id):
        data_store.pop(session_id, None)
        return True

    async def mock_exists(session_id):
        return session_id in data_store

    mock_store.read = AsyncMock(side_effect=mock_read)
    mock_store.write = AsyncMock(side_effect=mock_write)
    mock_store.remove = AsyncMock(side_effect=mock_remove)
    mock_store.exists = AsyncMock(side_effect=mock_exists)

    # Patch the app's store
    import nginx_ldap_auth.app.main

    mocker.patch.object(nginx_ldap_auth.app.main, "store", mock_store)
    for middleware in nginx_ldap_auth.app.main.app.user_middleware:
        if "SessionMiddleware" in str(middleware.cls):
            middleware.kwargs["store"] = mock_store
            # Force rebuild of middleware stack
            nginx_ldap_auth.app.main.app.middleware_stack = None

    mocker.patch.object(mock_settings, "session_backend", "redis")

    return mock_store, data_store


def test_duo_session_persistence(
    client, mock_user_manager, mock_duo_settings, mock_duo_client, redis_store
):
    """
    Test that the session is persisted between login_handler and the duo view.
    """
    mock_store, data_store = redis_store

    # 1. Perform LDAP login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "service": "/target",
            "csrf_token": "dummy",
        },
        follow_redirects=False,
    )

    assert login_response.status_code == status.HTTP_302_FOUND
    assert "/auth/duo" in login_response.headers["location"]

    # Check if we got a session cookie
    session_cookie_name = mock_duo_settings.cookie_name
    assert session_cookie_name in login_response.cookies
    session_id = login_response.cookies[session_cookie_name]

    # 2. Verify session was written to our mock store
    assert session_id in data_store
    raw_data = data_store[session_id]
    session_data = json.loads(raw_data) if isinstance(raw_data, bytes) else raw_data
    assert session_data.get("username") == "testuser"

    # 3. Access the /auth/duo view with the session cookie
    duo_response = client.get(
        "/auth/duo",
        params={"service": "/target"},
        cookies={session_cookie_name: session_id},
        follow_redirects=False,
    )

    # Verify that load_session was called in duo view
    assert mock_store.read.called

    assert duo_response.status_code in (
        status.HTTP_302_FOUND,
        status.HTTP_307_TEMPORARY_REDIRECT,
    )
    assert "duosecurity.com" in duo_response.headers["location"]

    # 4. Verify Duo state was added to the SAME session
    assert session_id in data_store
    raw_updated_data = data_store[session_id]
    if isinstance(raw_updated_data, bytes):
        updated_session_data = json.loads(raw_updated_data)
    else:
        updated_session_data = raw_updated_data

    assert updated_session_data.get("username") == "testuser"
    assert updated_session_data.get("duo_state") == "test_state"
    assert updated_session_data.get("duo_service") == "/target"


def test_duo_callback_success(
    client, mock_user_manager, mock_duo_settings, mock_duo_client, redis_store
):
    """
    Test a successful Duo callback.
    """
    _, data_store = redis_store

    # 1. Setup session with Duo state
    session_id = "test_session_id"
    data_store[session_id] = {
        "username": "testuser",
        "duo_state": "test_state",
        "duo_service": "/target",
    }

    # 2. Call the callback URL
    # We need to set the x-proto-scheme and host headers so the redirect_uri can
    # be built
    response = client.get(
        "/auth/duo/callback",
        params={"state": "test_state", "duo_code": "valid_code"},
        cookies={mock_duo_settings.cookie_name: session_id},
        headers={"x-proto-scheme": "https", "host": "localhost"},
        follow_redirects=False,
    )

    # 3. Verify redirect to original service
    assert response.status_code in (
        status.HTTP_302_FOUND,
        status.HTTP_307_TEMPORARY_REDIRECT,
    )
    assert response.headers["location"] == "/target"

    # 4. Verify session was updated
    raw_updated_data = data_store[session_id]
    if isinstance(raw_updated_data, bytes):
        updated_data = json.loads(raw_updated_data)
    else:
        updated_data = raw_updated_data
    assert updated_data["duo_authenticated"] is True
    assert "duo_state" not in updated_data
    assert "duo_service" not in updated_data


def test_duo_callback_state_mismatch(
    client, mock_user_manager, mock_duo_settings, mock_duo_client, redis_store
):
    """
    Test Duo callback with state mismatch.
    """
    _, data_store = redis_store

    # 1. Setup session with Duo state
    session_id = "test_session_id"
    data_store[session_id] = {
        "username": "testuser",
        "duo_state": "correct_state",
        "duo_service": "/target",
    }

    # 2. Call the callback URL with WRONG state
    response = client.get(
        "/auth/duo/callback",
        params={"state": "wrong_state", "duo_code": "valid_code"},
        cookies={mock_duo_settings.cookie_name: session_id},
        headers={"x-proto-scheme": "https", "host": "localhost"},
        follow_redirects=False,
    )

    # 3. Verify redirect back to login
    assert response.status_code in (
        status.HTTP_302_FOUND,
        status.HTTP_307_TEMPORARY_REDIRECT,
    )
    assert "/auth/login" in response.headers["location"]

    # 4. Verify session was NOT updated with authentication
    raw_updated_data = data_store[session_id]
    if isinstance(raw_updated_data, bytes):
        updated_data = json.loads(raw_updated_data)
    else:
        updated_data = raw_updated_data
    assert updated_data.get("duo_authenticated") is not True


def test_full_duo_flow(
    client, mock_user_manager, mock_duo_settings, mock_duo_client, redis_store
):
    """
    Test the full Duo flow from login to callback.
    """
    _, data_store = redis_store
    session_cookie_name = mock_duo_settings.cookie_name

    # 1. Login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "service": "/target",
            "csrf_token": "dummy",
        },
        follow_redirects=False,
    )
    assert login_response.status_code == status.HTTP_302_FOUND
    assert "/auth/duo" in login_response.headers["location"]
    session_id = login_response.cookies[session_cookie_name]

    # 2. Initiate Duo
    duo_init_response = client.get(
        "/auth/duo",
        params={"service": "/target"},
        cookies={session_cookie_name: session_id},
        headers={"x-proto-scheme": "https", "host": "localhost"},
        follow_redirects=False,
    )
    assert duo_init_response.status_code in (
        status.HTTP_302_FOUND,
        status.HTTP_307_TEMPORARY_REDIRECT,
    )
    assert "duosecurity.com" in duo_init_response.headers["location"]

    # Verify state was saved
    raw_data = data_store[session_id]
    session_data = json.loads(raw_data) if isinstance(raw_data, bytes) else raw_data
    state = session_data["duo_state"]
    assert state == "test_state"

    # 3. Callback
    callback_response = client.get(
        "/auth/duo/callback",
        params={"state": state, "duo_code": "valid_code"},
        cookies={session_cookie_name: session_id},
        headers={"x-proto-scheme": "https", "host": "localhost"},
        follow_redirects=False,
    )
    assert callback_response.status_code in (
        status.HTTP_302_FOUND,
        status.HTTP_307_TEMPORARY_REDIRECT,
    )
    assert callback_response.headers["location"] == "/target"

    # 4. Verify final session state
    raw_final_data = data_store[session_id]
    if isinstance(raw_final_data, bytes):
        final_data = json.loads(raw_final_data)
    else:
        final_data = raw_final_data
    assert final_data["duo_authenticated"] is True
    assert final_data["username"] == "testuser"


def test_duo_disabled_flow(
    client, mock_user_manager, mock_settings, redis_store, mocker
):
    """
    Test that the Duo flow is skipped when settings.duo_enabled is False.
    """
    mocker.patch.object(mock_settings, "duo_enabled", False)  # noqa: FBT003
    _, data_store = redis_store

    # 1. Perform LDAP login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "service": "/target",
            "csrf_token": "dummy",
        },
        follow_redirects=False,
    )

    # Should redirect directly to the service, NOT to /auth/duo
    assert login_response.status_code == status.HTTP_302_FOUND
    assert login_response.headers["location"] == "/target"

    # Check if we got a session cookie
    session_cookie_name = mock_settings.cookie_name
    assert session_cookie_name in login_response.cookies
    session_id = login_response.cookies[session_cookie_name]

    # 2. Verify session was written and duo_authenticated is False (or not present)
    assert session_id in data_store
    raw_data = data_store[session_id]
    session_data = json.loads(raw_data) if isinstance(raw_data, bytes) else raw_data
    assert session_data.get("username") == "testuser"
    assert session_data.get("duo_authenticated") is False
