"""Explicit MemAuth experiment profile metadata.

Import this submodule explicitly for offline experiments. This is not a
service-facing trusted-module API or a cross-protocol binding.
"""
from __future__ import annotations

from ..memauth import executable_profile as profile, srs

PROFILE_ID = profile.PROFILE_ID
ORDER = profile.ORDER


def load_srs(artifact: dict):
    """Validate an offline SRS artifact; it does not contain the setup trapdoor."""
    return srs.SRS.from_artifact(artifact)


def profile_manifest() -> dict:
    return profile.manifest()


__all__ = ["PROFILE_ID", "ORDER", "load_srs", "profile_manifest"]
