import pytest
from pydantic import ValidationError
from nginx_ldap_auth.settings import Settings


def make_settings(**kwargs):
    base_kwargs = {
        "secret_key": "secret",
        "ldap_uri": "ldap://localhost",
        "ldap_binddn": "cn=admin",
        "ldap_password": "password",
        "ldap_basedn": "dc=example,dc=com",
    }
    return Settings(**(base_kwargs | kwargs))


def test_settings_get_user_filter_validation():
    """
    Test that Settings validates ldap_get_user_filter.
    """
    # Valid filter (default)
    make_settings()

    # Invalid filter
    with pytest.raises(ValidationError) as excinfo:
        make_settings(ldap_get_user_filter="(invalid")
    assert "ldap_get_user_filter" in str(excinfo.value) or "ldap_authorization_filter" in str(excinfo.value)

def test_settings_authorization_filter_validation():
    """
    Test that Settings validates ldap_authorization_filter.
    """
    # Valid filter with {username}
    make_settings(ldap_authorization_filter="(&(memberOf=group)(uid={username}))")

    # Invalid filter (syntax)
    with pytest.raises(ValidationError):
        make_settings(ldap_authorization_filter="invalid)")

    # Invalid filter (missing {username})
    with pytest.raises(ValidationError) as excinfo:
        make_settings(ldap_authorization_filter="(objectClass=person)")
    assert "does not use the {username} placeholder" in str(excinfo.value)


def test_settings_authorization_filter_none_allowed():
    """
    Test that ldap_authorization_filter can be None.
    """
    settings = make_settings(ldap_authorization_filter=None)
    assert settings.ldap_authorization_filter is None


def test_settings_ca_cert_is_optional_by_default():
    """
    Test that CA cert settings are optional when both are unset.
    """
    settings = make_settings()
    assert settings.ldap_ca_cert_name is None
    assert settings.ldap_ca_cert_dir is None


def test_settings_ca_cert_name_requires_dir():
    """
    Test that ldap_ca_cert_name requires ldap_ca_cert_dir.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(ldap_ca_cert_name="ca.pem")
    assert "ldap_ca_cert_dir is required if ldap_ca_cert_name is set" in str(excinfo.value)


def test_settings_ca_cert_dir_requires_name(tmp_path):
    """
    Test that ldap_ca_cert_dir requires ldap_ca_cert_name.
    """
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    with pytest.raises(ValidationError) as excinfo:
        make_settings(ldap_ca_cert_dir=cert_dir)
    assert "ldap_ca_cert_name is required if ldap_ca_cert_dir is set" in str(excinfo.value)


def test_settings_ca_cert_dir_and_file_must_exist(tmp_path):
    """
    Test that CA cert directory and file paths are validated.
    """
    missing_dir = tmp_path / "missing"
    with pytest.raises(ValidationError) as excinfo:
        make_settings(ldap_ca_cert_name="ca.pem", ldap_ca_cert_dir=missing_dir)
    assert "ldap_ca_cert_dir does not exist" in str(excinfo.value)

    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    with pytest.raises(ValidationError) as excinfo:
        make_settings(ldap_ca_cert_name="ca.pem", ldap_ca_cert_dir=cert_dir)
    assert "ldap_ca_cert_name does not exist in ldap_ca_cert_dir" in str(excinfo.value)


def test_settings_ca_cert_valid_paths(tmp_path):
    """
    Test that valid CA cert directory and file pass validation.
    """
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    cert_file = cert_dir / "ca.pem"
    cert_file.write_text("dummy-cert")

    settings = make_settings(ldap_ca_cert_name="ca.pem", ldap_ca_cert_dir=cert_dir)
    assert settings.ldap_ca_cert_dir == cert_dir
    assert settings.ldap_ca_cert_name == "ca.pem"
