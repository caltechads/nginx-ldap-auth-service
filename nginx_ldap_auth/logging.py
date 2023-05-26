import logging
import logging.config
import os
import re
from typing import Any, Union, Type
from sentry_sdk import capture_exception
import structlog  # type: ignore

logger = structlog.get_logger('nginx_ldap_auth')


DEVELOPMENT: bool = os.environ.get('DEVELOPMENT', 'False') == 'True'
LOGLEVEL: str = os.environ.get('LOGLEVEL', 'INFO')


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
        for password_key_name in ('password', 'password1', 'password2'):
            if password_key_name in event_dict:
                event_dict[password_key_name] = '*CENSORED*'
        return event_dict


structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt='iso'),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        ContextLoggingProcessor(),
        CensorPasswordProcessor(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter
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
    structlog.processors.TimeStamper(fmt='iso'),
]

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'json': {
            'level': LOGLEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'json'
        },
        'null': {
            'level': LOGLEVEL,
            'class': 'logging.NullHandler',
        },
    },
    'loggers': {
        'aiohttp.access': {
            'handlers': ['json'],
            'propagate': False
        },
        'aiohttp.server': {
            'handlers': ['json']
        },
        'aiohttp.internal': {
            'handlers': ['json']
        },
        'aiohttp.web': {
            'handlers': ['json']
        },
        'aiohttp.websocket': {
            'handlers': ['json']
        },
        'aiohttp.client': {
            'handlers': ['json']
        }
    },
    'root': {
        # Set up the root logger.  This will make all otherwise unconfigured loggers log through structlog
        # processor.
        'handlers': ['json'],
        'level': LOGLEVEL
    },
    'formatters': {
        # Set up a special formatter for our structlog output
        'json': {
            '()': structlog.stdlib.ProcessorFormatter,
            'processor': structlog.processors.JSONRenderer(),
            'foreign_pre_chain': pre_chain,
            'format': '%(message)s'
        },
    },
}


def global_exc_handler(loop, data):
    logger.exception(
        'Unhandled exception',
        msg=data['message'],
        exc_info=True,
        exception=data['exception']
    )
    capture_exception(data['exception'])


logging.config.dictConfig(LOGGING)
