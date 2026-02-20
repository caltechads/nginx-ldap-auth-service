import pytest
from nginx_ldap_auth.validators import validate_ldap_search_filter

def test_validate_ldap_search_filter_valid():
    """
    Test validate_ldap_search_filter with a valid LDAP filter.
    """
    # Simple valid filter with required placeholder
    validate_ldap_search_filter("(uid={username})")
    # Filter with all placeholders
    validate_ldap_search_filter("({username_attribute}={username})")
    validate_ldap_search_filter("(&(objectClass=person)({username_full_name_attribute}=*{username}*))")

def test_validate_ldap_search_filter_missing_username_placeholder():
    """
    Test validate_ldap_search_filter when the {username} placeholder is missing.
    """
    # Valid LDAP syntax but missing {username}
    with pytest.raises(ValueError) as excinfo:
        validate_ldap_search_filter("(objectClass=*)")
    assert "does not use the {username} placeholder" in str(excinfo.value)

def test_validate_ldap_search_filter_invalid_syntax():
    """
    Test validate_ldap_search_filter with invalid LDAP syntax.
    """
    # Unbalanced parentheses
    with pytest.raises(ValueError) as excinfo:
        validate_ldap_search_filter("(objectClass=*")
    assert "not a valid LDAP filter" in str(excinfo.value)

    # Invalid characters/syntax
    with pytest.raises(ValueError):
        validate_ldap_search_filter("invalid filter")

def test_validate_ldap_search_filter_placeholder_formatting():
    """
    Test that placeholders are correctly handled (formatted) before parsing.
    """
    # This should not raise ParseError because validate_ldap_search_filter 
    # formats placeholders before passing to Filter.parse
    validate_ldap_search_filter("{username_attribute}={username}")
