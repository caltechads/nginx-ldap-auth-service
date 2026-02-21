import importlib
import ssl
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

import nginx_ldap_auth
from nginx_ldap_auth.cli.cli import cli


def test_cli_version():
    """
    Test the CLI version command.
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert nginx_ldap_auth.__version__ in result.output


def test_cli_settings():
    """
    Test the CLI settings command.
    """
    runner = CliRunner()
    # We need to import the command to register it with the cli group

    result = runner.invoke(cli, ["settings"])
    assert result.exit_code == 0
    assert "ldap_uri" in result.output
    assert "cookie_name" in result.output


def test_cli_start_help():
    """
    Test the CLI start command help.
    """
    runner = CliRunner()

    result = runner.invoke(cli, ["start", "--help"])
    assert result.exit_code == 0
    assert "Start the nginx_ldap_auth service." in result.output
    assert "--host" in result.output
    assert "--port" in result.output


def test_ssl_required_reflects_settings(monkeypatch):
    """
    Test that ssl_required follows the settings.insecure value.
    """
    from nginx_ldap_auth.cli import server

    monkeypatch.setattr(server.settings, "insecure", False)
    assert server.ssl_required() is True

    monkeypatch.setattr(server.settings, "insecure", True)
    assert server.ssl_required() is False


def test_cli_ssl_option_path_validation_uses_ssl_required():
    """
    Test that certfile/keyfile path validators use ssl_required.
    """
    from nginx_ldap_auth.cli import server

    keyfile_option = next(
        param for param in server.start.params if param.name == "keyfile"
    )
    certfile_option = next(
        param for param in server.start.params if param.name == "certfile"
    )

    assert keyfile_option.type.exists is server.ssl_required()
    assert certfile_option.type.exists is server.ssl_required()


def test_cli_start_insecure_env_skips_ssl_file_existence_check(monkeypatch):
    """
    Test that INSECURE=True disables SSL file existence checks at option setup.
    """
    import nginx_ldap_auth.cli.server as server_module

    monkeypatch.setenv("INSECURE", "True")
    reloaded_server = importlib.reload(server_module)
    try:
        keyfile_option = next(
            param for param in reloaded_server.start.params if param.name == "keyfile"
        )
        certfile_option = next(
            param for param in reloaded_server.start.params if param.name == "certfile"
        )
        assert keyfile_option.type.exists is False
        assert certfile_option.type.exists is False

        runner = CliRunner()
        with patch("uvicorn.run") as mock_run:
            result = runner.invoke(reloaded_server.cli, ["start"])

        assert result.exit_code == 0
        mock_run.assert_called_once()
        kwargs = mock_run.call_args.kwargs
        assert "ssl_keyfile" not in kwargs
        assert "ssl_certfile" not in kwargs
    finally:
        monkeypatch.delenv("INSECURE", raising=False)
        importlib.reload(server_module)


@patch("uvicorn.run")
def test_cli_start_insecure(mock_run, tmp_path):
    """
    Test the CLI start command with --insecure.
    """
    runner = CliRunner()

    # Create dummy SSL files just to satisfy the default Path(exists=True) check
    # even if we are using --insecure, because click validates defaults
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    key = tmp_path / "key.key"
    key.write_text("key")

    # Use boolean flag for --insecure
    result = runner.invoke(
        cli,
        [
            "start",
            "--insecure",
            "True",
            "--host",
            "127.0.0.1",
            "--port",
            "9999",
            "--certfile",
            str(cert),
            "--keyfile",
            str(key),
        ],
    )

    if result.exit_code != 0:
        print(f"CLI Output: {result.output}")  # noqa: T201

    assert result.exit_code == 0
    mock_run.assert_called_once()
    _, kwargs = mock_run.call_args
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 9999
    assert "ssl_keyfile" not in kwargs


@patch("uvicorn.run")
def test_cli_start_secure(mock_run, tmp_path):
    """
    Test the CLI start command with SSL files.
    """
    runner = CliRunner()

    # Create dummy SSL files
    cert = tmp_path / "cert.crt"
    cert.write_text("cert")
    key = tmp_path / "key.key"
    key.write_text("key")

    result = runner.invoke(
        cli, ["start", "--certfile", str(cert), "--keyfile", str(key)]
    )
    assert result.exit_code == 0
    mock_run.assert_called_once()
    kwargs = mock_run.call_args.kwargs
    assert kwargs["ssl_certfile"] == str(cert)
    assert kwargs["ssl_keyfile"] == str(key)


def test_cli_start_secure_uses_tls12_plus_and_not_sslv2(monkeypatch):
    """
    Test secure startup uses a TLS server context (TLS 1.2+) and not SSLv2.
    """
    import nginx_ldap_auth.cli.server as server_module

    monkeypatch.setenv("INSECURE", "False")
    reloaded_server = importlib.reload(server_module)
    try:
        cert = (
            Path(__file__).resolve().parents[1]
            / "etc"
            / "nginx"
            / "certs"
            / "localhost.crt"
        )
        key = (
            Path(__file__).resolve().parents[1]
            / "etc"
            / "nginx"
            / "certs"
            / "localhost.key"
        )
        runner = CliRunner()
        with patch("uvicorn.run") as mock_run:
            result = runner.invoke(
                reloaded_server.cli,
                ["start", "--certfile", str(cert), "--keyfile", str(key)],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()
        kwargs = mock_run.call_args.kwargs

        assert kwargs["ssl_version"] == ssl.PROTOCOL_TLS_SERVER
        tls_context = ssl.SSLContext(kwargs["ssl_version"])
        assert tls_context.minimum_version >= ssl.TLSVersion.TLSv1_2

        sslv2 = getattr(ssl, "PROTOCOL_SSLv2", None)
        if sslv2 is not None:
            assert kwargs["ssl_version"] != sslv2
    finally:
        monkeypatch.delenv("INSECURE", raising=False)
        importlib.reload(server_module)
