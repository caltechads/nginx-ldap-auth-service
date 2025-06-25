import logging
import logging.config
import sys
from typing import TYPE_CHECKING, Any, cast

import structlog
from fastapi import Request

from nginx_ldap_auth.settings import Settings

if TYPE_CHECKING:
    from starlette.datastructures import Address

settings = Settings()
logger = structlog.get_logger("nginx_ldap_auth")


def get_logger(request: Request | None = None) -> structlog.BoundLogger:
    """
    Return a structlog logger with request context information.

    Creates a logger that includes relevant request context when available, making
    it easier to trace logs related to specific requests.

    Note:
        When a request is provided, the logger is bound with the following values:

        * realm: The authentication realm (from x-auth-realm header or settings)
        * host: The server hostname (from host header)
        * remote_ip: The client IP address (from x-forwarded-for or request.client)


    Args:
        request: The FastAPI/Starlette request object. If provided, adds request
                context information to the logger.

    Returns:
        structlog.BoundLogger: A configured structlog logger with optional
        request context

    """
    if request is None:
        return logger
    remote_ip = request.headers.get("x-forwarded-for")
    if remote_ip:
        remote_ip = remote_ip.split(",")[0]
    else:
        remote_ip = cast("Address", request.client).host
    request = cast("Request", request)
    return logger.bind(
        realm=request.headers.get("x-auth-realm", settings.auth_realm),
        host=request.headers.get("host", "unknown"),
        remote_ip=remote_ip,
    )


class ContextLoggingProcessor:
    """
    Structlog processor that adds additional context to log events.

    This processor allows you to define default key-value pairs that will be
    added to all log events processed by structlog. Values provided explicitly
    during logging will take precedence over these defaults.

    Attributes:
        log_kwargs: Dictionary of key-value pairs to add to log events

    Example:
        To make all log events include ``app_name`` and ``environment`` unless
        explicitly overridden:

        .. code-block:: python

            import structlog
            from nginx_ldap_auth.logging import ContextLoggingProcessor

            # Create a processor that adds app_name and environment to all log events
            processor = ContextLoggingProcessor(
                app_name="my-app",
                environment="production"
            )

    """

    def __init__(self, **kwargs: Any) -> None:
        """
        Initialize the processor with context values.

        Args:
            **kwargs: Key-value pairs to add to all log events

        """
        self.log_kwargs = kwargs

    def __call__(self, _, __, event_dict):
        """
        Add context values to the log event dictionary.

        This processor adds all key-value pairs from the initialization to the
        event dictionary, but doesn't overwrite any existing values.

        Args:
            _: Logger (unused)
            __: Method name (unused)
            event_dict: The log event dictionary to modify

        Returns:
            dict: The modified log event dictionary

        """
        for k, v in self.log_kwargs.items():
            event_dict.setdefault(k, v)
        return event_dict


class CensorPasswordProcessor:
    """
    Structlog processor that censors password fields in log events.

    This processor automatically detects and censors common password field names
    in log events, preventing sensitive information from being logged.

    Attributes:
        log_kwargs: Additional configuration options (unused currently)

    Example:
        >>> # Add to structlog processors
        >>> processors = [
        >>>     # other processors
        >>>     CensorPasswordProcessor(),
        >>>     # more processors
        >>> ]

    """

    def __init__(self, **kwargs: Any) -> None:
        """
        Initialize the processor.

        Args:
            **kwargs: Configuration options (reserved for future use)

        """
        self.log_kwargs = kwargs

    def __call__(self, _, __, event_dict):
        """
        Censor password fields in the log event dictionary.

        Automatically identifies and censors values for keys named "password",
        "password1", or "password2" to prevent sensitive data from being logged.

        Args:
            _: Logger (unused)
            __: Method name (unused)
            event_dict: The log event dictionary to modify

        Returns:
            dict: The modified log event dictionary with passwords censored

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
