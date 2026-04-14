"""
Tests for the header-based authorization endpoint (/check-header).

This endpoint is designed for Kerberos/SPNEGO authentication where NGINX
handles authentication and passes the username via a trusted header.
"""

import pytest
from bonsai import LDAPError


@pytest.fixture(autouse=True)
def reset_auth_cache():
    """Reset the authorization cache before and after each test."""
    from nginx_ldap_auth.app.header_auth_cache import reset_cache

    reset_cache()
    yield
    reset_cache()


class TestCheckHeaderEndpoint:
    """Tests for the /check-header endpoint."""

    def test_check_header_success(self, client, mock_user_manager):
        """Test successful authorization with valid header and authorized user."""
        mock_user_manager.is_authorized.return_value = True

        response = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": (
                    "(&(uid={username})(memberOf=cn=admins,dc=example,dc=com))"
                ),
            },
        )

        assert response.status_code == 200
        assert response.headers.get("x-auth-user") == "testuser"
        assert response.headers.get("cache-control") == "no-cache"

    def test_check_header_missing_header(self, client, mock_user_manager):  # noqa: ARG002
        """Test that missing X-Ldap-User header returns 401."""
        response = client.get("/check-header")

        assert response.status_code == 401
        assert "x-auth-user" not in response.headers
        assert response.headers.get("cache-control") == "no-cache"

    def test_check_header_not_authorized(self, client, mock_user_manager):
        """Test that user not in required group returns 403."""
        mock_user_manager.is_authorized.return_value = False

        response = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": (
                    "(&(uid={username})(memberOf=cn=admins,dc=example,dc=com))"
                ),
            },
        )

        assert response.status_code == 403
        assert "x-auth-user" not in response.headers

    def test_check_header_no_filter_returns_500(
        self, client, mock_user_manager, mocker
    ):
        """Test that missing effective authorization filter returns 500."""
        from nginx_ldap_auth.app import header_auth

        mocker.patch.object(header_auth.settings, "ldap_authorization_filter", None)
        response = client.get(
            "/check-header",
            headers={"x-ldap-user": "testuser"},
        )

        assert response.status_code == 500
        assert response.headers.get("x-auth-user") is None
        mock_user_manager.is_authorized.assert_not_called()

    def test_check_header_ldap_error(self, client, mock_user_manager):
        """Test that LDAP errors return 500."""
        mock_user_manager.is_authorized.side_effect = LDAPError("Connection failed")

        response = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": (
                    "(&(uid={username})(memberOf=cn=admins,dc=example,dc=com))"
                ),
            },
        )

        assert response.status_code == 500

    def test_check_header_cache_hit(self, client, mock_user_manager):
        """Test that cached results are used (LDAP not queried on second request)."""
        mock_user_manager.is_authorized.return_value = True

        headers = {
            "x-ldap-user": "cacheuser",
            "x-authorization-filter": (
                "(&(uid={username})(memberOf=cn=testers,dc=example,dc=com))"
            ),
        }

        # First request - should query LDAP
        response1 = client.get("/check-header", headers=headers)
        assert response1.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 1

        # Second request - should use cache
        response2 = client.get("/check-header", headers=headers)
        assert response2.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 1  # Still 1 (cache hit)

    def test_check_header_cache_different_filters(self, client, mock_user_manager):
        """Test that different filters result in different cache entries."""
        mock_user_manager.is_authorized.return_value = True

        # Request with filter A
        response1 = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(memberOf=cn=groupA,dc=example,dc=com)",
            },
        )
        assert response1.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 1

        # Request with filter B - different cache key, queries LDAP again
        response2 = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(memberOf=cn=groupB,dc=example,dc=com)",
            },
        )
        assert response2.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 2

    def test_check_header_custom_header_name(self, client, mock_user_manager, mocker):  # noqa: ARG002
        """Test that custom header name from settings works."""
        from nginx_ldap_auth.app import header_auth

        mocker.patch.object(
            header_auth.settings, "ldap_trusted_user_header", "X-Remote-User"
        )
        mocker.patch.object(
            header_auth.settings,
            "ldap_authorization_filter",
            "(&(uid={username})(memberOf=cn=default,dc=example,dc=com))",
        )

        response = client.get(
            "/check-header",
            headers={"x-remote-user": "customuser"},
        )

        assert response.status_code == 200
        assert response.headers.get("x-auth-user") == "customuser"

    def test_check_header_uses_settings_filter(self, client, mock_user_manager, mocker):
        """Test that settings.ldap_authorization_filter is used when no header."""
        from nginx_ldap_auth.app import header_auth

        mocker.patch.object(
            header_auth.settings,
            "ldap_authorization_filter",
            "(&(uid={username})(memberOf=cn=default,dc=example,dc=com))",
        )
        mock_user_manager.is_authorized.return_value = True

        response = client.get(
            "/check-header",
            headers={"x-ldap-user": "testuser"},
        )

        assert response.status_code == 200
        mock_user_manager.is_authorized.assert_called_once()
        call_args = mock_user_manager.is_authorized.call_args
        assert "memberOf=cn=default" in call_args[0][1]

    def test_check_header_filter_header_ignored_when_disabled(
        self, client, mock_user_manager, mock_settings
    ):
        """Test that X-Authorization-Filter header is ignored when setting is False."""
        # Disable header override using the shared mock_settings fixture
        mock_settings.allow_authorization_filter_header = False
        mock_settings.ldap_authorization_filter = (
            "(memberOf=cn=allowed,dc=example,dc=com)"
        )
        mock_user_manager.is_authorized.return_value = True

        # Send request with malicious filter header (should be ignored)
        response = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(objectClass=*)",  # Malicious filter
            },
        )

        assert response.status_code == 200
        # Verify is_authorized was called with the setting filter, not the header
        mock_user_manager.is_authorized.assert_called_once()
        call_args = mock_user_manager.is_authorized.call_args
        assert call_args[0][1] == "(memberOf=cn=allowed,dc=example,dc=com)"
        assert "(objectClass=*)" not in str(call_args)


class TestAuthCache:
    """Tests for the authorization cache module."""

    @pytest.mark.asyncio
    async def test_cache_get_set(self):
        """Test cache get/set operations."""
        from nginx_ldap_auth.app.header_auth_cache import (
            get_cached_authorization,
            set_cached_authorization,
        )

        # Initially empty
        result = await get_cached_authorization("user1", "(filter1)")
        assert result is None

        # Set and get
        await set_cached_authorization("user1", "(filter1)", authorized=True)
        result = await get_cached_authorization("user1", "(filter1)")
        assert result is True

        # Different filter
        result = await get_cached_authorization("user1", "(filter2)")
        assert result is None

        # Set unauthorized
        await set_cached_authorization("user2", "(filter1)", authorized=False)
        result = await get_cached_authorization("user2", "(filter1)")
        assert result is False

    @pytest.mark.asyncio
    async def test_authorization_lock_prevents_concurrent_access(self):
        """Test that authorization_lock serializes access for same key."""
        import asyncio

        from nginx_ldap_auth.app.header_auth_cache import authorization_lock

        execution_order = []

        async def task(task_id: str, delay: float):
            async with authorization_lock("user1", "(filter1)"):
                execution_order.append(f"{task_id}_start")
                await asyncio.sleep(delay)
                execution_order.append(f"{task_id}_end")

        # Start two tasks concurrently for the same key
        await asyncio.gather(
            task("A", 0.1),
            task("B", 0.1),
        )

        # With locking, one task must complete before the other starts
        # Either A_start, A_end, B_start, B_end OR B_start, B_end, A_start, A_end
        assert execution_order[0].endswith("_start")
        assert execution_order[1].endswith("_end")
        assert execution_order[2].endswith("_start")
        assert execution_order[3].endswith("_end")

    @pytest.mark.asyncio
    async def test_authorization_lock_different_keys_concurrent(self):
        """Test that different keys can be accessed concurrently."""
        import asyncio

        from nginx_ldap_auth.app.header_auth_cache import authorization_lock

        execution_order = []

        async def task(task_id: str, username: str, delay: float):
            async with authorization_lock(username, "(filter1)"):
                execution_order.append(f"{task_id}_start")
                await asyncio.sleep(delay)
                execution_order.append(f"{task_id}_end")

        # Start two tasks concurrently for different keys
        await asyncio.gather(
            task("A", "user1", 0.1),
            task("B", "user2", 0.1),
        )

        # Different keys should allow concurrent access
        # Both should start before either ends
        starts = [e for e in execution_order if e.endswith("_start")]
        ends = [e for e in execution_order if e.endswith("_end")]

        # Both starts should happen before both ends (concurrent execution)
        first_end_idx = execution_order.index(ends[0])
        assert execution_order.index(starts[0]) < first_end_idx
        assert execution_order.index(starts[1]) < first_end_idx

    @pytest.mark.asyncio
    async def test_lock_lru_cleanup(self, mocker):
        """Test that locks are pruned when exceeding max limit."""
        from nginx_ldap_auth.app import header_auth_cache
        from nginx_ldap_auth.app.header_auth_cache import (
            authorization_lock,
            get_lock_count,
            reset_cache,
        )

        reset_cache()

        # Set a very low max to trigger cleanup easily
        mocker.patch.object(header_auth_cache, "_MAX_LOCKS", 5)

        # Create 6 locks (exceeds limit of 5)
        for i in range(6):
            async with authorization_lock(f"user{i}", "(filter)"):
                pass  # Just acquire and release

        # Should have pruned some locks (10% of 5 = 1, so 5 remain max)
        assert get_lock_count() <= 5

    @pytest.mark.asyncio
    async def test_lock_lru_does_not_prune_held_locks(self, mocker):
        """Test that currently held locks are not pruned."""
        import asyncio

        from nginx_ldap_auth.app import header_auth_cache
        from nginx_ldap_auth.app.header_auth_cache import (
            authorization_lock,
            reset_cache,
        )

        reset_cache()

        # Set a very low max to trigger cleanup
        mocker.patch.object(header_auth_cache, "_MAX_LOCKS", 3)

        release_event = asyncio.Event()

        async def hold_lock():
            async with authorization_lock("held_user", "(filter)"):
                # Wait while other locks are created
                await release_event.wait()

        async def create_locks():
            # Give the held lock time to acquire
            await asyncio.sleep(0.05)

            # Create more locks than max, should trigger pruning
            for i in range(5):
                async with authorization_lock(f"user{i}", "(filter)"):
                    pass

            release_event.set()

        # Run both concurrently - held lock should survive pruning
        await asyncio.gather(hold_lock(), create_locks())

        # Test completes without error - if held lock was pruned,
        # the context manager exit would fail
