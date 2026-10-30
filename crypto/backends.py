"""Pinned backend discovery for Batch 05 concrete providers."""

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version


PINNED_CRYPTOGRAPHY_VERSION = "50.0.2"


class BackendUnavailable(RuntimeError):
    """Raised when the reviewed backend is absent or has the wrong version."""


@dataclass(frozen=True)
class BackendInfo:
    package: str
    version: str
    pinned_version: str

    @property
    def matches_pin(self) -> bool:
        return self.version == self.pinned_version


def backend_info() -> BackendInfo:
    try:
        installed = version("cryptography")
    except PackageNotFoundError as exc:
        raise BackendUnavailable("cryptography is not installed") from exc
    return BackendInfo("cryptography", installed, PINNED_CRYPTOGRAPHY_VERSION)


def require_pinned_backend() -> BackendInfo:
    info = backend_info()
    if not info.matches_pin:
        raise BackendUnavailable(
            f"cryptography {info.version} is installed; Batch 05 requires {info.pinned_version}"
        )
    return info
