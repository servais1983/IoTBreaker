"""Timezone-aware UTC helpers.

``datetime.utcnow`` and ``datetime.utcfromtimestamp`` are deprecated and
return naive datetimes. These helpers always return aware UTC values.
"""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_from_timestamp(timestamp: float) -> datetime:
    """Convert a POSIX timestamp to an aware UTC datetime."""
    return datetime.fromtimestamp(timestamp, timezone.utc)
