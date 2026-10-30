"""Concrete adapters live in explicit submodules to keep boundaries acyclic."""

from .interfaces import CheckCode, CheckResult, SignatureProvider

__all__ = ["CheckCode", "CheckResult", "SignatureProvider"]
