from typing import TypeAlias  # noqa: A005

LDAPValue: TypeAlias = list[str]
LDAPObject: TypeAlias = dict[str, LDAPValue]
