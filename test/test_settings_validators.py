import pytest
from pydantic import ValidationError
from nginx_ldap_auth.settings import Settings

def test_settings_get_user_filter_validation():
    """
    Test that Settings validates ldap_get_user_filter.
    """
    # Valid filter (default)
    Settings(
        secret_key="secret",
        ldap_uri="ldap://localhost",
        ldap_binddn="cn=admin",
        ldap_password="password",
        ldap_basedn="dc=example,dc=com"
    )

    # Invalid filter
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            secret_key="secret",
            ldap_uri="ldap://localhost",
            ldap_binddn="cn=admin",
            ldap_password="password",
            ldap_basedn="dc=example,dc=com",
            ldap_get_user_filter="(invalid"
        )
    assert "ldap_get_user_filter" in str(excinfo.value) or "ldap_authorization_filter" in str(excinfo.value)

def test_settings_authorization_filter_validation():
    """
    Test that Settings validates ldap_authorization_filter.
    """
    # Valid filter with {username}
    Settings(
        secret_key="secret",
        ldap_uri="ldap://localhost",
        ldap_binddn="cn=admin",
        ldap_password="password",
        ldap_basedn="dc=example,dc=com",
        ldap_authorization_filter="(&(memberOf=group)(uid={username}))"
    )

    # Invalid filter (syntax)
    with pytest.raises(ValidationError):
        Settings(
            secret_key="secret",
            ldap_uri="ldap://localhost",
            ldap_binddn="cn=admin",
            ldap_password="password",
            ldap_basedn="dc=example,dc=com",
            ldap_authorization_filter="invalid)"
        )

    # Invalid filter (missing {username})
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            secret_key="secret",
            ldap_uri="ldap://localhost",
            ldap_binddn="cn=admin",
            ldap_password="password",
            ldap_basedn="dc=example,dc=com",
            ldap_authorization_filter="(objectClass=person)"
        )
    assert "does not use the {username} placeholder" in str(excinfo.value)

def test_settings_authorization_filter_none_allowed():
    """
    Test that ldap_authorization_filter can be None.
    """
    settings = Settings(
        secret_key="secret",
        ldap_uri="ldap://localhost",
        ldap_binddn="cn=admin",
        ldap_password="password",
        ldap_basedn="dc=example,dc=com",
        ldap_authorization_filter=None
    )
    assert settings.ldap_authorization_filter is None
