"""Headless DevSecOps pipeline audit — SAST for CI/CD configs."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("pipeline-audit")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]