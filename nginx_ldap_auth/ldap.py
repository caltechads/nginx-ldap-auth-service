import time
from typing import Any

import bonsai
from bonsai.asyncio import AIOConnectionPool, AIOLDAPConnection
from bonsai.pool import ClosedPool, EmptyPool

from .logging import logger
from .settings import Settings


class TimeLimitedAIOLDAPConnection(AIOLDAPConnection):
    """
    A time-limited LDAP connection.  This allows us to have a connection pool
    that will close connections after a certain amount of time.

    Args:
        client: The LDAP client.

    Keyword Args:
        expires: The number of seconds after which the connection will expire.
        loop: The asyncio event loop.

    """

    def __init__(self, client: bonsai.LDAPClient, expires: int = 20, loop=None) -> None:
        super().__init__(client, loop=loop)
        self.expires = expires
        self.create_time = time.time()

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.create_time) > self.expires


class TimeLimitedAIOConnectionPool(AIOConnectionPool):
    """
    A pool of time-limited LDAP connections.  This allows us to have relatively
    fresh connections to our LDAP server while not having to create a new
    connection for every request.

    Args:
        settings: The application settings.
        client: The LDAP client.

    Keyword Args:
        minconn: The minimum number of connections to keep in the pool.
        maxconn: The maximum number of connections to keep in the pool.
        loop: The asyncio event loop.

    """

    def __init__(
        self,
        settings: Settings,
        client: bonsai.LDAPClient,
        minconn: int = 1,
        maxconn: int = 10,
        loop=None,
        **kwargs: Any,
    ) -> None:
        super().__init__(client, minconn, maxconn, loop=loop, **kwargs)
        self.settings = settings

    async def get(self) -> AIOLDAPConnection:  # type: ignore[override]
        """
        Get a connection from the pool.  If a connection has expired, close it
        and create a new connection, then return the new connection.

        Raises:
            ClosedPool: The pool has not been initialized.
            EmptyPool: There are no connections in the pool.

        Returns:
            A connection from the pool.

        """
        async with self._lock:
            if self._closed:
                msg = "The pool is closed."
                raise ClosedPool(msg)
            await self._lock.wait_for(lambda: not self.empty or self._closed)
            try:
                conn = self._idles.pop()
            except KeyError:
                if len(self._used) < self._maxconn:
                    conn = await self._client.connect(
                        is_async=True, loop=self._loop, **self._kwargs
                    )
                else:
                    msg = "Pool is empty."
                    raise EmptyPool(msg) from None
            if conn.is_expired:
                logger.info(
                    "ldap.pool.connection.recycle",
                    lifetime_seconds=self.settings.ldap_pool_connection_lifetime_seconds,
                )
                # Does this need to be awaited?
                conn.close()
                conn = await self._client.connect(
                    is_async=True, loop=self._loop, **self._kwargs
                )
            self._used.add(conn)
            self._lock.notify()
            return conn
