import typing

from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import Message, Receive, Scope, Send
from starsessions import SessionMiddleware as StarsessionsSessionMiddleware
from starsessions.middleware import LoadGuard
from starsessions.session import SessionHandler, get_session_remaining_seconds


class SessionMiddleware(StarsessionsSessionMiddleware):
    """
    Override the :py:class:`starsession.SessionMiddleware` to allow us to set
    the cookie name and domain via the ``X-Cookie-Name`` and ``X-Cookie-Domain``
    headers, respectively.  If those headers are not present, the values from
    the constructor are used.

    We need this so that we can set the cookie name and domain dynamically based
    on the request.  This is necessary because we may have multiple nginx severs
    that use a single ``nginx_ldap_auth`` server for authentication.

    Note:
        Unfortunately, the  :py:meth:``__call__`` method is monolithic in the
        superclass, so we have to re-implement it here in is entirety to do
        what we want to do.

    """

    #: The header name for the cookie name passed in by nginx.
    COOKIE_NAME_HEADER: typing.Final[str] = "X-Cookie-Name"
    #: The header name for the cookie domain passed in by nginx.
    COOKIE_DOMAIN_HEADER: typing.Final[str] = "X-Cookie-Domain"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        cookie_name = connection.headers.get(self.COOKIE_NAME_HEADER, self.cookie_name)
        cookie_domain = connection.headers.get(
            self.COOKIE_DOMAIN_HEADER, self.cookie_domain
        )
        session_id = connection.cookies.get(cookie_name)
        handler = SessionHandler(
            connection, session_id, self.store, self.serializer, self.lifetime
        )

        scope["session"] = LoadGuard()
        scope["session_handler"] = handler

        async def send_wrapper(message: Message) -> None:
            if message["type"] != "http.response.start":
                await send(message)
                return

            if not handler.is_loaded:  # session was not loaded, do nothing
                await send(message)
                return

            nonlocal session_id
            path = self.cookie_path or scope.get("root_path", "") or "/"

            if handler.is_empty:
                # if session was initially empty then do nothing
                if handler.initially_empty:
                    await send(message)
                    return

                # session data loaded but empty, no matter whether it was
                # initially empty or cleared we have to remove the cookie and
                # clear the storage
                if not self.cookie_path or (
                    self.cookie_path and scope["path"].startswith(self.cookie_path)
                ):
                    headers = MutableHeaders(scope=message)
                    header_value = "{}={}; {}".format(
                        cookie_name,
                        f"null; path={path}; expires=Thu, 01 Jan 1970 00:00:00 GMT;",
                        self.security_flags,
                    )
                    headers.append("Set-Cookie", header_value)
                    await handler.destroy()
                await send(message)
                return

            # calculate cookie/storage expiry seconds based on selected strategy
            remaining_time = 0

            # if lifetime is zero then don't send max-age at all
            # this will create session-only cookie
            if self.lifetime > 0:
                if self.rolling:
                    # rolling strategy always extends cookie max-age by lifetime
                    remaining_time = self.lifetime
                else:
                    # non-rolling strategy reuses initial expiration date
                    remaining_time = get_session_remaining_seconds(connection)

            # persist session data
            session_id = await handler.save(remaining_time)

            headers = MutableHeaders(scope=message)
            header_parts = [
                f"{cookie_name}={session_id}",
                f"path={path}",
            ]

            if self.lifetime > 0:  # always send max-age for non-session scoped cookie
                header_parts.append(f"max-age={remaining_time}")

            if cookie_domain:
                header_parts.append(f"domain={cookie_domain}")

            header_parts.append(self.security_flags)
            header_value = "; ".join(header_parts)
            headers.append("set-cookie", header_value)

            await send(message)

        await self.app(scope, receive, send_wrapper)
