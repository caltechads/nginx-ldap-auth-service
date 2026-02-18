from unittest.mock import AsyncMock


def test_check_no_cookie(client, mock_user_manager):
    """
    Test /check when no session cookie is present.
    """
    response = client.get("/check")
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-cache"


def test_check_valid_session(client, mock_user_manager):
    """
    Test /check with a valid session.
    """
    # 1. Login to get a session
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "csrf_token": "dummy",
            "service": "/check",
        },
    )
    assert login_response.status_code == 302
    cookie = login_response.cookies.get("nginxauth")

    # 2. Call /check
    response = client.get("/check", cookies={"nginxauth": cookie})
    assert response.status_code == 200
    assert response.json() == {}


def test_check_user_no_longer_exists(client, mock_user_manager):
    """
    Test /check when the user in the session no longer exists in LDAP.
    """
    # 1. Login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "csrf_token": "dummy",
            "service": "/check",
        },
    )
    cookie = login_response.cookies.get("nginxauth")

    # 2. Mock user no longer exists
    mock_user_manager.get.side_effect = AsyncMock(return_value=None)

    # 3. Call /check
    response = client.get("/check", cookies={"nginxauth": cookie})
    assert response.status_code == 401


def test_check_with_authorization_filter_header(
    client, mock_user_manager, mock_settings
):
    """
    Test /check with X-Authorization-Filter header when allowed.
    """
    # Ensure header is allowed (default)
    mock_settings.allow_authorization_filter_header = True

    # 1. Login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "csrf_token": "dummy",
            "service": "/check",
        },
    )
    cookie = login_response.cookies.get("nginxauth")

    # 2. Call /check with filter header
    mock_user_manager.is_authorized.side_effect = AsyncMock(return_value=False)
    response = client.get(
        "/check",
        headers={
            "x-authorization-filter": "(&(group=admin)({username_attribute}={username}))"
        },
        cookies={"nginxauth": cookie},
    )

    assert response.status_code == 401
    # Check that it was called with the filter from the header
    mock_user_manager.is_authorized.assert_called()
    found = False
    for call in mock_user_manager.is_authorized.call_args_list:
        if (
            len(call.args) > 1
            and call.args[1] == "(&(group=admin)({username_attribute}={username}))"
        ):
            found = True
            break
    assert found, (
        "is_authorized was not called with expected filter header. "
        f"Calls: {mock_user_manager.is_authorized.call_args_list}"
    )


def test_check_authorization_filter_header_ignored_when_disabled(
    client, mock_user_manager, mock_settings
):
    """
    Test that X-Authorization-Filter header is ignored when
    allow_authorization_filter_header is False.
    """
    # Disable header override
    mock_settings.allow_authorization_filter_header = False
    mock_settings.ldap_authorization_filter = "(group=allowed)"

    # 1. Login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "csrf_token": "dummy",
            "service": "/check",
        },
    )
    cookie = login_response.cookies.get("nginxauth")

    # 2. Call /check with malicious filter header (should be ignored)
    mock_user_manager.is_authorized.reset_mock()
    mock_user_manager.is_authorized.side_effect = AsyncMock(return_value=True)
    response = client.get(
        "/check",
        headers={"x-authorization-filter": "(objectClass=*)"},  # Malicious filter
        cookies={"nginxauth": cookie},
    )

    assert response.status_code == 200
    # Check that it was called with the setting value, NOT the header value
    mock_user_manager.is_authorized.assert_called()
    found_setting_filter = False
    found_header_filter = False
    for call in mock_user_manager.is_authorized.call_args_list:
        if len(call.args) > 1:
            if call.args[1] == "(group=allowed)":
                found_setting_filter = True
            if call.args[1] == "(objectClass=*)":
                found_header_filter = True
    assert found_setting_filter, (
        "is_authorized should have been called with (group=allowed) from settings. "
        f"Calls: {mock_user_manager.is_authorized.call_args_list}"
    )
    assert not found_header_filter, (
        "is_authorized should NOT have been called with (objectClass=*) from header. "
        f"Calls: {mock_user_manager.is_authorized.call_args_list}"
    )


def test_session_middleware_custom_cookie_name(client, mock_user_manager):
    """
    Test SessionMiddleware with X-Cookie-Name header.
    """
    # 1. Login with custom cookie name
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "csrf_token": "dummy",
            "service": "/check",
        },
        headers={"x-cookie-name": "custom_cookie"},
    )

    assert response.status_code == 302
    cookie = response.cookies.get("custom_cookie")
    assert cookie is not None

    # 2. Call /check with custom cookie
    response = client.get(
        "/check",
        headers={"x-cookie-name": "custom_cookie"},
        cookies={"custom_cookie": cookie},
    )
    assert response.status_code == 200


def test_x_authenticated_user_header(client, mock_user_manager):
    """
    Test that x-authenticated-user header is set in response.
    """
    # 1. Login
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "csrf_token": "dummy",
            "service": "/check",
        },
    )

    # 2. Check header in login response
    assert response.headers["x-authenticated-user"] == "testuser"

    # 3. Check header in /check response
    cookie = response.cookies.get("nginxauth")
    response = client.get("/check", cookies={"nginxauth": cookie})
    assert response.headers["x-authenticated-user"] == "testuser"


def test_check_invalid_authorization_filter_header(client, mock_user_manager):
    """
    Test /check with an invalid X-Authorization-Filter header.
    """
    # 1. Login to get a session
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "csrf_token": "dummy",
            "service": "/check",
        },
    )
    cookie = login_response.cookies.get("nginxauth")

    # 2. Call /check with an invalid filter header
    # This should raise a ValueError in the app, which FastAPI 
    # will catch and return as a 500 Internal Server Error by default 
    # if not explicitly handled.
    try:
        response = client.get(
            "/check",
            headers={"x-authorization-filter": "(invalid-filter"},
            cookies={"nginxauth": cookie},
        )
        assert response.status_code == 500
    except ValueError:
        # If raise_server_exceptions=True, TestClient will raise the exception
        pass
