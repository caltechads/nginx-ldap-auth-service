import pytest
from fastapi import HTTPException, status
from starlette.datastructures import Headers
from structlog.testing import capture_logs

from nginx_ldap_auth.app.main import check_required_headers, validate_service_url
from nginx_ldap_auth.exc import ImproperlyConfigured


class MockRequest:
    """
    Mock request object for testing.
    """

    def __init__(self, headers=None, query_params=None):
        self.headers = Headers(headers or {})
        self.query_params = query_params or {}
        self.scope = {"type": "http", "headers": self.headers.raw}


def test_check_required_headers_golden_path():
    """
    Test check_required_headers with all required headers present.
    """
    headers = {
        "x-proto-scheme": "https",
        "x-host": "example.com",
        "host": "example.com",
    }
    request = MockRequest(headers=headers)

    # Should not raise any exception
    check_required_headers(request)


def test_check_required_headers_missing_proto():
    """
    Test check_required_headers when X-Proto-Scheme is missing.
    """
    headers = {"x-host": "example.com", "host": "example.com"}
    request = MockRequest(headers=headers)

    with capture_logs() as captured:
        with pytest.raises(ImproperlyConfigured) as excinfo:
            check_required_headers(request)

        assert "X-Proto-Scheme" in str(excinfo.value)

        # Check logs
        assert any(
            log["event"] == "check_required_headers.missing"
            and log["header"] == "X-Proto-Scheme"
            and log["log_level"] == "error"
            for log in captured
        )


def test_check_required_headers_missing_xhost():
    """
    Test check_required_headers when X-Host is missing.
    """
    headers = {"x-proto-scheme": "https", "host": "example.com"}
    request = MockRequest(headers=headers)

    with capture_logs() as captured:
        with pytest.raises(ImproperlyConfigured) as excinfo:
            check_required_headers(request)

        assert "X-Host" in str(excinfo.value)

        # Check logs
        assert any(
            log["event"] == "check_required_headers.missing"
            and log["header"] == "X-Host"
            and log["log_level"] == "error"
            for log in captured
        )


def test_check_required_headers_both_missing():
    """
    Test check_required_headers when both headers are missing.
    It should fail on the first one (X-Proto-Scheme).
    """
    headers = {"host": "example.com"}
    request = MockRequest(headers=headers)

    with capture_logs() as captured:
        with pytest.raises(ImproperlyConfigured) as excinfo:
            check_required_headers(request)

        assert "X-Proto-Scheme" in str(excinfo.value)

        # Check logs
        assert any(
            log["event"] == "check_required_headers.missing"
            and log["header"] == "X-Proto-Scheme"
            for log in captured
        )


def test_check_required_headers_success_log():
    """
    Test that success is logged at debug level.
    """
    headers = {
        "x-proto-scheme": "https",
        "x-host": "example.com",
        "host": "example.com",
    }
    request = MockRequest(headers=headers)

    with capture_logs() as captured:
        check_required_headers(request)

        assert any(
            log["event"] == "check_required_headers.success"
            and log["x_proto_scheme"] == "https"
            and log["log_level"] == "debug"
            for log in captured
        )


@pytest.mark.asyncio
async def test_validate_service_url_golden_path():
    """
    Test validate_service_url with valid headers and service URL.
    """
    headers = {
        "x-proto-scheme": "https",
        "x-host": "example.com",
        "host": "example.com",
    }
    request = MockRequest(headers=headers)

    # Test with absolute URL matching base
    service = "https://example.com/target"
    result = await validate_service_url(request, service=service)
    assert result == service

    # Test with relative URL
    service = "/relative/path"
    result = await validate_service_url(request, service=service)
    assert result == service


@pytest.mark.asyncio
async def test_validate_service_url_invalid():
    """
    Test validate_service_url with an invalid service URL.
    """
    headers = {
        "x-proto-scheme": "https",
        "x-host": "example.com",
        "host": "example.com",
    }
    request = MockRequest(headers=headers)

    # Different host
    service = "https://malicious.com/target"
    with pytest.raises(HTTPException) as excinfo:
        await validate_service_url(request, service=service)
    assert excinfo.value.status_code == status.HTTP_400_BAD_REQUEST
    assert excinfo.value.detail == "Invalid URL requested"

    # Different scheme
    service = "http://example.com/target"
    with pytest.raises(HTTPException) as excinfo:
        await validate_service_url(request, service=service)
    assert excinfo.value.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_validate_service_url_from_query_params():
    """
    Test validate_service_url when service is taken from query params.
    """
    headers = {
        "x-proto-scheme": "https",
        "x-host": "example.com",
        "host": "example.com",
    }
    query_params = {"service": "/from-query"}
    request = MockRequest(headers=headers, query_params=query_params)

    result = await validate_service_url(request)
    assert result == "/from-query"


@pytest.mark.asyncio
async def test_validate_service_url_default():
    """
    Test validate_service_url default value when no service provided.
    """
    headers = {
        "x-proto-scheme": "https",
        "x-host": "example.com",
        "host": "example.com",
    }
    request = MockRequest(headers=headers)

    result = await validate_service_url(request)
    assert result == "/"
