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
