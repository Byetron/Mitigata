"""Failure classification (brief 2.3): every failure maps to exactly one category. Pure functions."""
from __future__ import annotations

from enum import StrEnum

import httpx

from .security.errors import SecretNotFoundError


class FailureCategory(StrEnum):
    AUTH_FAILED = "auth_failed"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    NETWORK = "network"
    SCHEMA_CHANGED = "schema_changed"
    BAD_DATA = "bad_data"
    CLIENT_ERROR = "client_error"
    UNKNOWN = "unknown"


_AUTH_STATUSES = {401, 403}
_FIRST_ERROR_STATUS = 400
_FIRST_SERVER_STATUS = 500


def classify_status(status: int) -> FailureCategory | None:
    """HTTP status to category. None means the status is not a failure."""
    if status < _FIRST_ERROR_STATUS:
        return None
    if status in _AUTH_STATUSES:
        return FailureCategory.AUTH_FAILED
    if status == 404:  # noqa: PLR2004
        return FailureCategory.NOT_FOUND
    if status == 429:  # noqa: PLR2004
        return FailureCategory.RATE_LIMITED
    if status >= _FIRST_SERVER_STATUS:
        return FailureCategory.SERVER_ERROR
    return FailureCategory.CLIENT_ERROR


def classify_exception(exc: BaseException) -> FailureCategory:
    """Exception to category. Anything unrecognised is `unknown`."""
    category = getattr(exc, "category", None)  # FetchError already carries its category
    if isinstance(category, FailureCategory):
        return category
    if isinstance(exc, httpx.TransportError):
        return FailureCategory.NETWORK
    if isinstance(exc, SecretNotFoundError):
        return FailureCategory.AUTH_FAILED
    return FailureCategory.UNKNOWN
