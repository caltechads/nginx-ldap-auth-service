def test_login_page_get(client, mocker, mock_user_manager):
    """
    Test the login page GET request.
    """

    # Mock set_csrf_cookie to actually set a cookie for this test
    def side_effect(token, response):
        response.set_cookie("nginxauth_csrf", token)

    mocker.patch(
        "fastapi_csrf_protect.CsrfProtect.set_csrf_cookie", side_effect=side_effect
    )

    response = client.get("/auth/login?service=/target")
    assert response.status_code == 200
    assert "nginxauth_csrf" in response.cookies
    assert 'name="service" value="/target"' in response.text


def test_login_success(client, mock_user_manager):
    """
    Test successful login.
    """
    # 1. Post login credentials
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "service": "/target",
            "csrf_token": "dummy",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/target"
    assert "nginxauth" in response.cookies


def test_login_failure_invalid_credentials(client, mock_user_manager):
    """
    Test login failure with invalid credentials.
    """
    mock_user = mock_user_manager.get.return_value
    mock_user.authenticate.return_value = False

    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "wrongpassword",
            "csrf_token": "dummy",
        },
    )

    assert response.status_code == 200
    assert "Invalid username or password" in response.text


def test_login_failure_no_user(client, mock_user_manager):
    """
    Test login failure when user doesn't exist in LDAP.
    """
    mock_user_manager.get.return_value = None

    response = client.post(
        "/auth/login",
        data={"username": "nonexistent", "password": "password", "csrf_token": "dummy"},
    )

    assert response.status_code == 200
    assert "Invalid username or password" in response.text


def test_logout(client, mock_user_manager):
    """
    Test logout.
    """
    # 1. Login first to have a session
    client.post(
        "/auth/login",
        data={"username": "testuser", "password": "password", "csrf_token": "dummy"},
    )

    # 2. Now logout
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/auth/login?service=/"


def test_login_authorization_filter_header_ignored_when_disabled(
    client, mock_user_manager, mock_settings
):
    """
    Test that X-Authorization-Filter header is ignored during login when
    allow_authorization_filter_header is False.
    """
    from unittest.mock import AsyncMock

    # Disable header override
    mock_settings.allow_authorization_filter_header = False
    mock_settings.ldap_authorization_filter = "(group=allowed)"

    # Make is_authorized return True only for the correct filter
    def is_authorized_side_effect(username, filter_value):
        # Return True only for the expected filter, False for malicious ones
        return filter_value == "(group=allowed)"

    mock_user_manager.is_authorized.side_effect = AsyncMock(
        side_effect=is_authorized_side_effect
    )

    # Attempt login with malicious filter header (should be ignored)
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "password",
            "service": "/target",
            "csrf_token": "dummy",
        },
        headers={"x-authorization-filter": "(objectClass=*)"},  # Malicious filter
        follow_redirects=False,
    )

    # Should succeed because the setting filter is used, not the header
    assert response.status_code == 302
    assert response.headers["location"] == "/target"
