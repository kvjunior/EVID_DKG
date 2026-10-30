"""Small, bounded, injective binary encoding used by protocol messages.

Parsing produces bytes and integers only.  In particular, a parsed byte string
does not become a group element, commitment, signature, or accepted anchor.
Those transitions belong to the configured cryptographic boundary.
"""

from dataclasses import dataclass
from typing import Final


MAX_BLOB: Final = 1 << 20
MAX_TEXT: Final = 255
MAX_ITEMS: Final = 1 << 16


class EncodingError(ValueError):
    """Raised for a non-canonical or out-of-contract wire representation."""


def _bounded(value: int, bits: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EncodingError(f"{name} must be an integer")
    if value < 0 or value >= 1 << bits:
        raise EncodingError(f"{name} does not fit u{bits}")
    return value


def u8(value: int) -> bytes:
    return _bounded(value, 8, "value").to_bytes(1, "big")


def u16(value: int) -> bytes:
    return _bounded(value, 16, "value").to_bytes(2, "big")


def u32(value: int) -> bytes:
    return _bounded(value, 32, "value").to_bytes(4, "big")


def u64(value: int) -> bytes:
    return _bounded(value, 64, "value").to_bytes(8, "big")


def blob(value: bytes, *, maximum: int = MAX_BLOB) -> bytes:
    if not isinstance(value, bytes):
        raise EncodingError("blob must be immutable bytes")
    if len(value) > maximum:
        raise EncodingError("blob exceeds its configured limit")
    return u32(len(value)) + value


def text(value: str, *, maximum: int = MAX_TEXT) -> bytes:
    if not isinstance(value, str):
        raise EncodingError("text must be str")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EncodingError("text must be ASCII") from exc
    if not raw or len(raw) > maximum:
        raise EncodingError("text length is outside its configured limits")
    return u8(len(raw)) + raw


def sequence(items: tuple[bytes, ...], *, maximum: int = MAX_ITEMS) -> bytes:
    if len(items) > maximum:
        raise EncodingError("too many sequence items")
    return u16(len(items)) + b"".join(blob(item) for item in items)


@dataclass
class Reader:
    data: bytes
    offset: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise EncodingError("wire input must be immutable bytes")

    def _take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise EncodingError("truncated encoding")
        out = self.data[self.offset:self.offset + count]
        self.offset += count
        return out

    def fixed(self, count: int) -> bytes:
        """Read an exact-size field without adding a second length prefix."""
        return self._take(count)

    def u8(self) -> int:
        return int.from_bytes(self._take(1), "big")

    def u16(self) -> int:
        return int.from_bytes(self._take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self._take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self._take(8), "big")

    def blob(self, *, maximum: int = MAX_BLOB) -> bytes:
        length = self.u32()
        if length > maximum:
            raise EncodingError("declared blob exceeds its configured limit")
        return self._take(length)

    def text(self, *, maximum: int = MAX_TEXT) -> str:
        length = self.u8()
        if length == 0 or length > maximum:
            raise EncodingError("declared text length is invalid")
        try:
            return self._take(length).decode("ascii")
        except UnicodeDecodeError as exc:
            raise EncodingError("text is not ASCII") from exc

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise EncodingError("trailing bytes")


def decode_exact(data: bytes, decoder):
    reader = Reader(data)
    value = decoder(reader)
    reader.finish()
    return value
