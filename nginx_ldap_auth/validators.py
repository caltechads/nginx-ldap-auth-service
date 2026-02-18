from ldap_filter import Filter, ParseError


def _parse_ldap_search_filter(
    filter_string: str,
    ldap_username_attribute: str,
    ldap_full_name_attribute: str,
) -> None:
    """
    Parse an LDAP filter after formatting supported placeholders.

    Raises:
        ValueError: The LDAP search filter is not a valid LDAP filter
    """
    try:
        # Filters can have placeholders for various values, so we need to
        # format the filter with the actual values so that Filter.parse()
        # won't blow up on the placeholders.
        Filter.parse(
            filter_string.format(
                username_attribute=ldap_username_attribute,
                username_full_name_attribute=ldap_full_name_attribute,
                username="foo",
            )
        )
    except ParseError as e:
        msg = f"ldap_authorization_filter is not a valid LDAP filter: {e}"
        raise ValueError(msg) from e


def validate_ldap_search_filter(
    filter_string: str,
    ldap_username_attribute: str = "uid",
    ldap_full_name_attribute: str = "cn",
) -> None:
    """
    Validate that a given LDAP search filter is valid.

    We're assuming that the filter string has our normal placeholders:

    - ``{username_attribute}``
    - ``{username_full_name_attribute}``
    - ``{username}``

    We'll format the filter with the actual values so that Filter.parse()
    won't blow up on the placeholders.

    Args:
        filter_string: The LDAP search filter to validate
        ldap_username_attribute: The LDAP attribute to use as the username
        ldap_full_name_attribute: The LDAP attribute to use as the full name

    Raises:
        ValueError: The LDAP search filter is not a valid LDAP filter
        ValueError: The LDAP search filter does not use the {username} placeholder

    """
    _parse_ldap_search_filter(
        filter_string,
        ldap_username_attribute=ldap_username_attribute,
        ldap_full_name_attribute=ldap_full_name_attribute,
    )

    # Now check that the filter actually uses the {username} placeholder
    if "{username}" not in filter_string:
        msg = "ldap_authorization_filter does not use the {username} placeholder"
        raise ValueError(msg)
