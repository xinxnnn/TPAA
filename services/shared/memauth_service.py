"""Reserved for future MemAuth process integration.

The standalone experiment in demos/memauth/registration_memory.py runs all
roles in one process. Wiring it into this service would expose issuer, AP and
PA secrets inside a business process and misrepresent an in-process fixture as
the agreed independent trusted module. No enrollment endpoint is enabled until
those role boundaries, authenticated delivery and durable state exist.
"""


class EnrollmentUnavailable(RuntimeError):
    """The verified platform runtime has no trusted MemAuth enrollment service."""


def require_trusted_module() -> None:
    raise EnrollmentUnavailable(
        "MemAuth enrollment requires an independent PA module and TP/AP role services"
    )
