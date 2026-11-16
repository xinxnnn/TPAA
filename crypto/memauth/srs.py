"""Public dual-group SRS (PDF Phase 0), with no trapdoor field."""
from dataclasses import dataclass
from hashlib import sha256

from . import pairing_backend as backend
from .polynomial import Polynomial


@dataclass(frozen=True)
class SRS:
    g1_powers: tuple[bytes, ...]
    g2_powers: tuple[bytes, ...]

    def __post_init__(self):
        object.__setattr__(self, 'g1_powers', tuple(self.g1_powers))
        object.__setattr__(self, 'g2_powers', tuple(self.g2_powers))
        if len(self.g1_powers) != len(self.g2_powers) or len(self.g1_powers) < 2:
            raise ValueError('SRS requires matching G1/G2 sequences of degree at least one')
        for group, powers in ((1, self.g1_powers), (2, self.g2_powers)):
            for point in powers:
                backend.validate(point, group)
                if point == backend.identity(group):
                    raise ValueError('Nonzero setup alpha requires nonidentity SRS powers')
            if powers[0] != backend.generator(group):
                raise ValueError('SRS base generator mismatch')
        for i in range(1, len(self.g1_powers)):
            if not backend.pairing_equal(self.g1_powers[i], self.g2_powers[0],
                                         self.g1_powers[i-1], self.g2_powers[1]):
                raise ValueError('Inconsistent G1 SRS power')
            if not backend.pairing_equal(self.g1_powers[0], self.g2_powers[i],
                                         self.g1_powers[1], self.g2_powers[i-1]):
                raise ValueError('Inconsistent G2 SRS power')

    @property
    def maximum_degree(self):
        return len(self.g1_powers) - 1

    @property
    def identifier(self):
        # Local artifact identifier, NOT an extra baseline protocol field.
        return sha256(b'memauth-srs-bls12-381-v1\x00' +
                      b''.join(self.g1_powers) + b''.join(self.g2_powers)).hexdigest()

    def to_artifact(self):
        """Local setup artifact; this is not a baseline protocol message."""
        return {
            'format': 'memauth-experiment-srs-bls12-381-v1',
            'srsId': self.identifier,
            'maximumDegree': self.maximum_degree,
            'g1Powers': [p.hex() for p in self.g1_powers],
            'g2Powers': [p.hex() for p in self.g2_powers],
        }

    @classmethod
    def from_artifact(cls, artifact):
        if artifact['format'] != 'memauth-experiment-srs-bls12-381-v1':
            raise ValueError('Unknown SRS artifact format')
        srs = cls(tuple(bytes.fromhex(p) for p in artifact['g1Powers']),
                  tuple(bytes.fromhex(p) for p in artifact['g2Powers']))
        if artifact['srsId'] != srs.identifier or artifact['maximumDegree'] != srs.maximum_degree:
            raise ValueError('SRS artifact metadata mismatch')
        return srs

    def commit(self, polynomial: Polynomial, group: int = 1) -> bytes:
        if polynomial.q != backend.ORDER:
            raise ValueError('Polynomial and SRS scalar fields differ')
        polynomial.require_degree(self.maximum_degree)
        if group not in (1, 2):
            raise ValueError('Expected group 1 or 2')
        powers = self.g1_powers if group == 1 else self.g2_powers
        result = backend.identity(group)
        for coefficient, point in zip(polynomial.coefficients, powers):
            result = backend.add(result, backend.multiply(point, coefficient, group), group)
        return result
