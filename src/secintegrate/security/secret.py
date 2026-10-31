"""A secret value that cannot leak through repr(), str() or f-strings."""
from __future__ import annotations


class Secret:
    """Wraps a secret string. The only way to read it is reveal()."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    def __str__(self) -> str:
        return "***"
