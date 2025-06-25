from typing import TypeAlias

LDAPValue: TypeAlias = list[str]
LDAPObject: TypeAlias = dict[str, LDAPValue]
