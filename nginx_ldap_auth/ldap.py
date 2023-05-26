#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
from typing import Any

import bonsai
from bonsai.asyncio import AIOConnectionPool, AIOLDAPConnection
from bonsai.pool import ClosedPool, EmptyPool

from .logging import logger
from .settings import Settings


class TimeLimitedAIOLDAPConnection(AIOLDAPConnection):

    def __init__(
        self,
        client: bonsai.LDAPClient,
        expires: int = 20,
        loop=None
    ) -> None:
        super().__init__(client, loop=loop)
        self.expires = expires
        self.create_time = time.time()

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.create_time) > self.expires


class TimeLimitedAIOConnectionPool(AIOConnectionPool):

    def __init__(
        self,
        settings: Settings,
        client: bonsai.LDAPClient,
        minconn: int = 1,
        maxconn: int = 10,
        loop=None,
        **kwargs: Any
    ) -> None:
        super().__init__(client, minconn, maxconn, loop=loop, **kwargs)
        self.settings = settings

    async def get(self) -> AIOLDAPConnection:
        async with self._lock:
            if self._closed:
                raise ClosedPool("The pool is closed.")
            await self._lock.wait_for(lambda: not self.empty or self._closed)
            try:
                conn = self._idles.pop()
            except KeyError:
                if len(self._used) < self._maxconn:
                    conn = await self._client.connect(
                        is_async=True, loop=self._loop, **self._kwargs
                    )
                else:
                    raise EmptyPool("Pool is empty.") from None
            if conn.is_expired:
                logger.info(
                    'ldap.pool.connection.recycle',
                    lifetime_seconds=self.settings.ldap_pool_connection_lifetime_seconds
                )
                # Does this need to be awaited?
                conn.close()
                conn = await self._client.connect(
                    is_async=True, loop=self._loop, **self._kwargs
                )
            self._used.add(conn)
            self._lock.notify()
            return conn
