import logging  # noqa: A005
import logging.config
import sys
from typing import Any, cast

import structlog
from fastapi import Request
from starlette.datastructures import Address

from nginx_ldap_auth.settings import Settings

settings = Settings()
logger = structlog.get_logger("nginx_ldap_auth")


def get_logger(request: Request | None = None) -> structlog.BoundLogger:
    """
    Return a structlog logger.  If a request is passed, bind the following
    values to the logger:

    * The name of the authentication realm (the title of the login window)
    * The host name of the server that asked us to authenticate/authorize
    * The IP address of the client that wants to authenticate/authorize

    Args:
        request: The request object

    Returns:
        A structlog logger

    """
    if request is None:
        return logger
    remote_ip = request.headers.get("x-forwarded-for")
    if remote_ip:
        remote_ip = remote_ip.split(",")[0]
    else:
        remote_ip = cast(Address, request.client).host
    request = cast(Request, request)
    return logger.bind(
        realm=request.headers.get("x-auth-realm", settings.auth_realm),
        host=request.headers.get("host", "unknown"),
        remote_ip=remote_ip,
    )


class ContextLoggingProcessor:
    def __init__(self, **kwargs: Any) -> None:
        self.log_kwargs = kwargs

    def __call__(self, _, __, event_dict):
        """
        Adds extra runtime event info to our log messages based on what was
        passed to our constructor.

        Does not overwrite any event info that's already been set in the logging
        call.
        """
        for k, v in self.log_kwargs.items():
            event_dict.setdefault(k, v)
        return event_dict


class CensorPasswordProcessor:
    def __init__(self, **kwargs: Any) -> None:
        self.log_kwargs = kwargs

    def __call__(self, _, __, event_dict):
        """
        Automatically censors any logging context key called "password",
        "password1", or "password2".
        """
        for password_key_name in ("password", "password1", "password2"):
            if password_key_name in event_dict:
                event_dict[password_key_name] = "*CENSORED*"
        return event_dict


structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        ContextLoggingProcessor(),
        CensorPasswordProcessor(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=False,
)

pre_chain = [
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {
        "default": {
            "level": settings.loglevel,
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
        "access": {"class": "logging.StreamHandler", "formatter": "access"},
    },
    "loggers": {
        "uvicorn.error": {
            "level": settings.loglevel,
            "handlers": ["default"],
            "propagate": False,
        },
        "uvicorn.access": {
            "level": settings.loglevel,
            "handlers": ["access"],
            "propagate": False,
        },
    },
    "root": {
        # Set up the root logger.  This will make all otherwise unconfigured
        # loggers log through structlog processor.
        "handlers": ["default"],
        "level": settings.loglevel,
    },
    "formatters": {
        "default": {
            "()": structlog.stdlib.ProcessorFormatter,
            "processor": structlog.processors.JSONRenderer(),
            "foreign_pre_chain": pre_chain,
            "format": "%(message)s",
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "format": "%(asctime)s %(message)s",
        },
    },
}


if settings.log_type == "text":
    LOGGING["formatters"]["default"]["processor"] = structlog.dev.ConsoleRenderer()  # type: ignore[index]


logging.config.dictConfig(LOGGING)


def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Log any uncaught exception instead of letting it be printed by Python
    (but leave KeyboardInterrupt untouched to allow users to Ctrl+C to stop)
    See https://stackoverflow.com/a/16993115/3641865
    """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = handle_exception
