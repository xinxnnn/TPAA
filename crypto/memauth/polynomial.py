"""Exact scalar-field polynomial arithmetic (PDF p7, equations 3 and CREATE).

Coefficients are ascending, normalized modulo q. This module implements no
pairing, commitment, hash encoding, or implicit paper errata.
"""
from dataclasses import dataclass

BLS12_381_SCALAR_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


def _supported_prime(q: int) -> bool:
    if q == BLS12_381_SCALAR_ORDER:
        return True
    if q < 2 or q >= 2**64:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if q % p == 0:
            return q == p
    d, s = q - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Deterministic Miller-Rabin bases for unsigned 64-bit integers.
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if a % q == 0:
            continue
        x = pow(a, d, q)
        if x in (1, q - 1):
            continue
        for _ in range(s - 1):
            x = x * x % q
            if x == q - 1:
                break
        else:
            return False
    return True


@dataclass(frozen=True)
class Polynomial:
    q: int
    coefficients: tuple[int, ...]

    def __post_init__(self):
        if type(self.q) is not int or not _supported_prime(self.q):
            raise ValueError('Unsupported prime field order')
        if any(type(c) is not int for c in self.coefficients):
            raise TypeError('Coefficients must be integers')
        cs = [c % self.q for c in self.coefficients] or [0]
        while len(cs) > 1 and cs[-1] == 0:
            cs.pop()
        object.__setattr__(self, 'coefficients', tuple(cs))

    @property
    def degree(self):
        return -1 if self.coefficients == (0,) else len(self.coefficients) - 1

    def __call__(self, x: int) -> int:
        value = 0
        for c in reversed(self.coefficients):
            value = (value * x + c) % self.q
        return value

    def _same_field(self, other):
        if not isinstance(other, Polynomial) or self.q != other.q:
            raise ValueError('Polynomial field mismatch')

    def __add__(self, other):
        self._same_field(other)
        a, b = self.coefficients, other.coefficients
        return Polynomial(self.q, tuple(
            (a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)
            for i in range(max(len(a), len(b)))))

    def scale(self, scalar: int):
        return Polynomial(self.q, tuple(c * scalar for c in self.coefficients))

    def __sub__(self, other):
        self._same_field(other)
        return self + other.scale(-1)

    def __mul__(self, other):
        self._same_field(other)
        cs = [0] * (len(self.coefficients) + len(other.coefficients) - 1)
        for i, a in enumerate(self.coefficients):
            for j, b in enumerate(other.coefficients):
                cs[i+j] = (cs[i+j] + a*b) % self.q
        return Polynomial(self.q, tuple(cs))

    def divide(self, divisor):
        self._same_field(divisor)
        if divisor.degree < 0:
            raise ZeroDivisionError('Zero polynomial divisor')
        rem = self
        quotient = [0] * max(1, self.degree - divisor.degree + 1)
        inverse = pow(divisor.coefficients[-1], -1, self.q)
        while rem.degree >= divisor.degree:
            shift = rem.degree - divisor.degree
            factor = rem.coefficients[-1] * inverse % self.q
            quotient[shift] = factor
            rem = rem - Polynomial(self.q, (0,) * shift + divisor.scale(factor).coefficients)
        return Polynomial(self.q, tuple(quotient)), rem

    def exact_divide(self, divisor):
        quotient, remainder = self.divide(divisor)
        if remainder.degree >= 0:
            raise ValueError('Polynomial division has nonzero remainder')
        return quotient

    def require_degree(self, maximum: int):
        if type(maximum) is not int or maximum < 0:
            raise ValueError('Maximum degree must be a nonnegative integer')
        if self.degree > maximum:
            raise ValueError('Polynomial degree exceeds SRS capacity')
        return self


def vanishing(q: int, coordinates) -> Polynomial:
    result = Polynomial(q, (1,))
    for x in coordinates:
        result = result * Polynomial(q, (-x, 1))
    return result


def interpolate(q: int, points) -> Polynomial:
    result = Polynomial(q, (0,))
    points = tuple((x % q, y % q) for x, y in points)
    if not points:
        raise ValueError('Interpolation requires at least one point')
    if len({x for x, _ in points}) != len(points):
        raise ValueError('Duplicate field coordinates')
    for i, (x, y) in enumerate(points):
        basis = vanishing(q, (other for j, (other, _) in enumerate(points) if j != i))
        result = result + basis.scale(y * pow(basis(x), -1, q))
    return result
