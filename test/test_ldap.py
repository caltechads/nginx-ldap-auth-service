import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import bonsai
import pytest

from nginx_ldap_auth.app.models import User, UserManager
from nginx_ldap_auth.ldap import (
    TimeLimitedAIOConnectionPool,
    TimeLimitedAIOLDAPConnection,
)
from nginx_ldap_auth.settings import Settings


@pytest.mark.asyncio
async def test_user_manager_authenticate_success(mocker):
    """
    Test UserManager.authenticate success.
    """
    mock_client = MagicMock()
    mock_client.connect = AsyncMock()
    mocker.patch("bonsai.LDAPClient", return_value=mock_client)

    manager = UserManager()
    result = await manager.authenticate("testuser", "password")

    assert result is True
    mock_client.set_credentials.assert_called_with(
        "SIMPLE",
        user="uid=testuser,dc=example,dc=com",
        password="password",  # noqa: S106
    )
    mock_client.connect.assert_called()


@pytest.mark.asyncio
async def test_user_manager_authenticate_failure(mocker):
    """
    Test UserManager.authenticate failure.
    """
    from bonsai.errors import AuthenticationError

    mock_client = MagicMock()
    mock_client.connect = AsyncMock(
        side_effect=AuthenticationError("Invalid credentials")
    )
    mocker.patch("bonsai.LDAPClient", return_value=mock_client)

    manager = UserManager()
    result = await manager.authenticate("testuser", "wrong")

    assert result is False


@pytest.mark.asyncio
async def test_user_manager_get_user(mocker):
    """
    Test UserManager.get user.
    """
    mock_conn = MagicMock()
    # Mock search result: list of tuples (DN, attributes)
    mock_entry = MagicMock()
    mock_entry.__getitem__.side_effect = lambda key: {
        "uid": ["testuser"],
        "cn": ["Test User"],
    }[key]
    mock_conn.search = AsyncMock(return_value=[mock_entry])

    mock_pool = MagicMock()
    mock_pool.spawn.return_value.__aenter__.return_value = mock_conn

    manager = UserManager()
    manager.pool = mock_pool

    user = await manager.get("testuser")

    assert user is not None
    assert user.uid == "testuser"
    assert user.full_name == "Test User"
    mock_conn.search.assert_called()


@pytest.mark.asyncio
async def test_user_manager_is_authorized(mocker):
    """
    Test UserManager.is_authorized.
    """
    mock_conn = MagicMock()
    mock_conn.search = AsyncMock(return_value=["some_result"])

    mock_pool = MagicMock()
    mock_pool.spawn.return_value.__aenter__.return_value = mock_conn

    manager = UserManager()
    manager.pool = mock_pool

    # Test with filter
    result = await manager.is_authorized("testuser", "(group=admin)")
    assert result is True
    mock_conn.search.assert_called()

    # Test without filter
    result = await manager.is_authorized("testuser", None)
    assert result is True


@pytest.mark.asyncio
async def test_user_manager_exists(mocker):
    """
    Test UserManager.exists.
    """
    mock_user = MagicMock(spec=User)

    manager = UserManager()
    with patch.object(manager, "get", AsyncMock(return_value=mock_user)):
        assert await manager.exists("testuser") is True

    with patch.object(manager, "get", AsyncMock(return_value=None)):
        assert await manager.exists("testuser") is False


@pytest.mark.asyncio
async def test_user_authenticate_method(mocker):
    """
    Test User.authenticate method.
    """
    user = User(uid="testuser", full_name="Test User")
    with patch.object(
        UserManager, "authenticate", AsyncMock(return_value=True)
    ) as mock_auth:
        assert await user.authenticate("password") is True
        mock_auth.assert_called_with("testuser", "password")


@pytest.mark.asyncio
async def test_user_manager_create_pool(mocker):
    """
    Test UserManager.create_pool.
    """
    mock_client = MagicMock()
    mocker.patch("bonsai.LDAPClient", return_value=mock_client)

    # Mock TimeLimitedAIOConnectionPool
    mock_pool_class = mocker.patch(
        "nginx_ldap_auth.app.models.TimeLimitedAIOConnectionPool"
    )
    mock_pool_instance = mock_pool_class.return_value
    mock_pool_instance.open = AsyncMock()

    manager = UserManager()
    await manager.create_pool()

    assert manager.pool == mock_pool_instance
    mock_pool_instance.open.assert_called_once()


@pytest.mark.asyncio
async def test_user_manager_cleanup(mocker):
    """
    Test UserManager.cleanup.
    """
    mock_pool = MagicMock()
    mock_pool.close = AsyncMock()

    manager = UserManager()
    manager.pool = mock_pool

    await manager.cleanup()
    mock_pool.close.assert_called_once()


@pytest.mark.asyncio
async def test_user_manager_authenticate_ad(mocker):
    """
    Test UserManager.authenticate with AD settings.
    """
    mock_client = MagicMock()
    mock_client.connect = AsyncMock()
    mocker.patch("bonsai.LDAPClient", return_value=mock_client)

    manager = UserManager()
    # Mock AD settings
    manager.settings.ldap_user_basedn = "@example.com"

    result = await manager.authenticate("testuser", "password")

    assert result is True
    mock_client.set_credentials.assert_called_with(
        "SIMPLE",
        user="testuser@example.com",
        password="password",  # noqa: S106
    )


@pytest.mark.asyncio
async def test_user_manager_is_authorized_no_pool(mocker):
    """
    Test UserManager.is_authorized creates pool if not exists.
    """
    mock_conn = MagicMock()
    mock_conn.search = AsyncMock(return_value=["some_result"])

    mock_pool = MagicMock()
    mock_pool.spawn.return_value.__aenter__.return_value = mock_conn

    manager = UserManager()

    # Mock create_pool to set the pool
    async def side_effect():
        manager.pool = mock_pool

    with patch.object(manager, "create_pool", AsyncMock(side_effect=side_effect)):
        result = await manager.is_authorized("testuser", "(group=admin)")
        assert result is True
        assert manager.pool == mock_pool


@pytest.mark.asyncio
async def test_user_manager_get_no_pool(mocker):
    """
    Test UserManager.get creates pool if not exists.
    """
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.__getitem__.side_effect = lambda key: {"uid": ["u"], "cn": ["n"]}[key]
    mock_conn.search = AsyncMock(return_value=[mock_entry])

    mock_pool = MagicMock()
    mock_pool.spawn.return_value.__aenter__.return_value = mock_conn

    manager = UserManager()

    async def side_effect():
        manager.pool = mock_pool

    with patch.object(manager, "create_pool", AsyncMock(side_effect=side_effect)):
        await manager.get("testuser")
        assert manager.pool == mock_pool


@pytest.mark.asyncio
async def test_time_limited_connection_init(mocker):
    """
    Test TimeLimitedAIOLDAPConnection initialization.
    """
    mock_client = mocker.Mock(spec=bonsai.LDAPClient)
    loop = asyncio.get_running_loop()
    conn = TimeLimitedAIOLDAPConnection(mock_client, expires=10, loop=loop)
    assert conn.expires == 10
    assert conn.create_time <= time.time()
    assert conn.is_expired is False

    # Test expiration
    conn.create_time = time.time() - 20
    assert conn.is_expired is True


@pytest.mark.asyncio
async def test_time_limited_connection_pool_recycle(mocker):
    """
    Test that TimeLimitedAIOConnectionPool recycles expired connections.
    """
    mock_client = mocker.Mock(spec=bonsai.LDAPClient)
    # First connection is expired, second one is new
    mock_conn_expired = MagicMock(spec=TimeLimitedAIOLDAPConnection)
    mock_conn_expired.is_expired = True
    mock_conn_expired.close = MagicMock()

    mock_conn_new = MagicMock(spec=TimeLimitedAIOLDAPConnection)
    mock_conn_new.is_expired = False

    # connect will be called once to replace the expired one
    mock_client.connect = AsyncMock(return_value=mock_conn_new)

    settings = Settings()
    pool = TimeLimitedAIOConnectionPool(settings, mock_client, minconn=1, maxconn=1)

    # Manually populate pool with expired connection
    pool._idles.add(mock_conn_expired)
    pool._opened = True
    pool._closed = False

    # Get connection from pool
    conn = await asyncio.wait_for(pool.get(), timeout=1.0)

    # The conn returned should be the new one
    assert conn == mock_conn_new
    mock_conn_expired.close.assert_called()
    assert mock_client.connect.call_count == 1


@pytest.mark.asyncio
async def test_time_limited_connection_pool_get_empty_pool(mocker):
    """
    Test TimeLimitedAIOConnectionPool.get when pool is empty but not at maxconn.
    """
    mock_client = mocker.Mock(spec=bonsai.LDAPClient)
    mock_conn = MagicMock(spec=TimeLimitedAIOLDAPConnection)
    mock_conn.is_expired = False
    mock_client.connect = AsyncMock(return_value=mock_conn)

    settings = Settings()
    pool = TimeLimitedAIOConnectionPool(settings, mock_client, minconn=1, maxconn=2)
    pool._opened = True
    pool._closed = False
    # _idles is empty, _used is empty

    conn = await asyncio.wait_for(pool.get(), timeout=1.0)
    assert conn == mock_conn
    assert mock_client.connect.call_count == 1


@pytest.mark.asyncio
async def test_time_limited_connection_pool_get_full_pool(mocker):
    """
    Test TimeLimitedAIOConnectionPool.get when pool is at maxconn.
    """
    mock_client = mocker.Mock(spec=bonsai.LDAPClient)
    settings = Settings()
    pool = TimeLimitedAIOConnectionPool(settings, mock_client, minconn=1, maxconn=1)
    pool._opened = True
    pool._closed = False

    # Fill the pool
    mock_conn_used = MagicMock(spec=TimeLimitedAIOLDAPConnection)
    pool._used.add(mock_conn_used)

    # We expect it to raise EmptyPool because maxconn is reached and _idles is empty
    # In a real scenario, it would wait on the lock, but since we're not
    # notifying the lock from another task, it will just timeout if we use wait_for.
    # However, the code logic for EmptyPool is only reached if pop() fails AND
    # len(_used) >= maxconn.

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(pool.get(), timeout=0.1)


@pytest.mark.asyncio
async def test_time_limited_connection_pool_closed(mocker):
    """
    Test TimeLimitedAIOConnectionPool.get when pool is closed.
    """
    from bonsai.pool import ClosedPool

    mock_client = mocker.Mock(spec=bonsai.LDAPClient)
    settings = Settings()
    pool = TimeLimitedAIOConnectionPool(settings, mock_client)
    pool._closed = True

    with pytest.raises(ClosedPool):
        await pool.get()
