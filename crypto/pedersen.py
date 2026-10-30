"""Executable Pedersen polynomial relation over RFC 5114 MODP group 24.

This is a transparent research/reference backend.  It is not an audited
deployment library and must not be used to claim production VESS security.
"""

from dataclasses import dataclass
from hashlib import shake_256


_P_HEX = """
87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00
E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C
209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B
6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76
B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E
F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026
C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103
A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
"""
P = int("".join(_P_HEX.split()), 16)
Q = int("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16)
G = int("".join("""
3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125
10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62
901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B
777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193
B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A
DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915
B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3
2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
""".split()), 16)
ELEMENT_BYTES = 256
SCALAR_BYTES = 32


def _derive_h() -> int:
    candidate = int.from_bytes(
        shake_256(b"EVID-DKG/Pedersen-H/RFC5114-group24/v1").digest(ELEMENT_BYTES), "big"
    ) % P
    h = pow(candidate, (P - 1) // Q, P)
    if h in (0, 1):
        raise RuntimeError("derived Pedersen generator is degenerate")
    return h


H = _derive_h()


def encode_scalar(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value < Q:
        raise ValueError("scalar is outside the RFC 5114 group-24 subgroup order")
    return value.to_bytes(SCALAR_BYTES, "big")


def decode_scalar(raw: bytes) -> int:
    if not isinstance(raw, bytes) or len(raw) != SCALAR_BYTES:
        raise ValueError("scalar must use the fixed 32-byte encoding")
    value = int.from_bytes(raw, "big")
    if value >= Q:
        raise ValueError("non-canonical scalar")
    return value


def encode_element(value: int) -> bytes:
    if not 1 < value < P - 1 or pow(value, Q, P) != 1:
        raise ValueError("invalid non-identity subgroup element")
    return value.to_bytes(ELEMENT_BYTES, "big")


def decode_element(raw: bytes) -> int:
    if not isinstance(raw, bytes) or len(raw) != ELEMENT_BYTES:
        raise ValueError("group element must use the fixed 256-byte encoding")
    value = int.from_bytes(raw, "big")
    if not 1 < value < P - 1 or pow(value, Q, P) != 1:
        raise ValueError("invalid or identity subgroup element")
    return value


def evaluate(coefficients: tuple[int, ...], point: int) -> int:
    acc = 0
    for coefficient in reversed(coefficients):
        acc = (acc * point + coefficient) % Q
    return acc


@dataclass(frozen=True)
class PedersenPolynomialCommitment:
    elements: tuple[bytes, ...]

    @classmethod
    def commit(cls, values: tuple[int, ...], blindings: tuple[int, ...]) -> "PedersenPolynomialCommitment":
        if not values or len(values) != len(blindings):
            raise ValueError("value and blinding polynomials must have equal positive length")
        elements = tuple(
            encode_element((pow(G, value % Q, P) * pow(H, blinding % Q, P)) % P)
            for value, blinding in zip(values, blindings, strict=True)
        )
        return cls(elements)

    @property
    def degree(self) -> int:
        return len(self.elements) - 1

    def verify(self, index: int, share: int, blinding_share: int) -> bool:
        if not 1 <= index < Q or not 0 <= share < Q or not 0 <= blinding_share < Q:
            return False
        try:
            decoded = tuple(decode_element(item) for item in self.elements)
        except ValueError:
            return False
        left = (pow(G, share, P) * pow(H, blinding_share, P)) % P
        right = 1
        power = 1
        for commitment in decoded:
            right = (right * pow(commitment, power, P)) % P
            power = (power * index) % Q
        return left == right

    def matches_polynomials(self, values: tuple[int, ...], blindings: tuple[int, ...]) -> bool:
        try:
            return self == self.commit(values, blindings)
        except ValueError:
            return False
