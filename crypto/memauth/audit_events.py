"""Approved experiment audit envelope, separate from baseline messages.

Only explicit public projections enter this API. No generic object/dictionary
redaction: internal credential objects, identity data and secrets are not inputs.
Provenance records an observation, not a signature or proof of execution.
"""
from dataclasses import dataclass
import hashlib

from . import pairing_backend as b
from . import executable_profile as profile
from .encoding import encode_value

METHOD = 'memauth-experiment-audit-v1'


@dataclass(frozen=True)
class APConstructPublic:
    """RF is the actual Paillier ciphertext output, not H(PII) or a CMC digest."""
    regulatory_ciphertext: int

    def __post_init__(self):
        if type(self.regulatory_ciphertext) is not int or self.regulatory_ciphertext <= 0:
            raise ValueError('Actual positive RF ciphertext required')


@dataclass(frozen=True)
class TPFinalizePublic:
    pa_public_key: bytes
    delta_tp: bytes

    def __post_init__(self):
        b.validate(self.pa_public_key, 1)
        b.validate(self.delta_tp, 1)


@dataclass(frozen=True)
class AuditEvent:
    time: str
    action: str
    object_digest: str
    subject: str
    method: str
    source_operation: str
    source_fields: tuple[str, ...]
    public_encoding: bytes
    public_output: APConstructPublic | TPFinalizePublic

    def event_tuple(self):
        return (self.time, self.action, self.object_digest, self.subject, self.method)

    @property
    def event_digest(self):
        return profile.h2(self.event_tuple())

    def public_trace(self):
        return {
            'scope': 'experiment observation; not authenticated protocol evidence',
            'profileId': profile.PROFILE_ID,
            'event': list(self.event_tuple()),
            'sourceOperation': self.source_operation,
            'sourceFields': list(self.source_fields),
            'publicProjectionEncodingHex': self.public_encoding.hex(),
            'H2': str(self.event_digest),
            'privacy': 'registration-correlatable public artifacts; not an anonymous transcript',
        }


def observe(time: str, role_did: str, output: APConstructPublic | TPFinalizePublic) -> AuditEvent:
    if any(type(value) is not str or not value for value in (time, role_did)):
        raise ValueError('Explicit operation time and role DID required')
    if type(output) is APConstructPublic:
        operation = 'PAConstruct'
        fields = ('RF',)
        values = (output.regulatory_ciphertext,)
    elif type(output) is TPFinalizePublic:
        operation = 'PHCFinalize'
        fields = ('PK_PA', 'delta_TP')
        values = (output.pa_public_key, output.delta_tp)
    else:
        raise TypeError('Only explicit AP/TP public output projections are accepted')
    encoded = encode_value((METHOD, operation, fields, values))
    digest = hashlib.sha256(encoded).hexdigest()
    return AuditEvent(time, operation, 'sha256:' + digest, role_did, METHOD,
                      operation, fields, encoded, output)


def initial_memory(srs, y0: int, pa_did: str, pa_public_key: bytes,
                   tp_event: AuditEvent, ap_event: AuditEvent, *, tp_rho: int, ap_rho: int):
    """Explicit PA-side experiment adapter. Does not issue or authenticate a PHC."""
    from .synthetic_macro import construct
    from .memory import build

    for event, operation in ((tp_event, 'PHCFinalize'), (ap_event, 'PAConstruct')):
        if type(event) is not AuditEvent or event.source_operation != operation:
            raise ValueError('TP/AP initial sequence provenance mismatch')
        if observe(event.time, event.subject, event.public_output) != event:
            raise ValueError('Audit envelope integrity mismatch')
    if tp_event.public_output.pa_public_key != pa_public_key:
        raise ValueError('Audit PA key does not match memory owner')
    tp_macro = construct('audit:tp', tp_event.time, pa_did, (tp_event.event_tuple(),),
                         pa_public_key, randomness=tp_rho)
    ap_macro = construct('audit:ap', ap_event.time, pa_did, (ap_event.event_tuple(),),
                         pa_public_key, randomness=ap_rho)
    state = build(srs, y0, tp_macro.point, ap_macro.point)
    return state, tp_macro, ap_macro
