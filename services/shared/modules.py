"""Load service modules by slash-separated path.

Service directories contain hyphens, which cannot appear in an import statement,
but are supported by importlib when given as a module-name string. This helper
keeps that lookup convention in one place for in-process adapters.
"""

from __future__ import annotations

import importlib
from types import ModuleType


def service_module(service: str, submodule: str = "") -> ModuleType:
    """Load `services/<service>` or one of its submodules.

    service can be `tp-side/did-service`, `ap-side/lifecycle-service`, or
    `cross-domain/audit-service`; submodule is dotted, such as `domain.usecases`.
    """
    name = "services." + service.replace("/", ".").replace("-side", "_side").replace("cross-domain", "cross_domain").replace("-", "_").strip(".")
    if submodule:
        name = f"{name}.{submodule}"
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"Cannot load {name}; check the service path and package initializers."
        ) from exc


__all__ = ["service_module"]
