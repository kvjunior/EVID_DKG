"""Serialized-size helpers; object counts are never treated as byte counts."""


def byte_length(value: bytes) -> int:
    if not isinstance(value, bytes):
        raise TypeError("serialized value must be immutable bytes")
    return len(value)
