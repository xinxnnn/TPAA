"""BLS12-381 research backend using real py_ecc groups and pairings.

Public boundaries use canonical compressed bytes, with curve/subgroup checks.
py_ecc/Python execution is not constant-time or hardware secret protection.
"""
from py_ecc import optimized_bls12_381 as curve
from py_ecc.bls.point_compression import (
    compress_G1, compress_G2, decompress_G1, decompress_G2,
)

from .polynomial import BLS12_381_SCALAR_ORDER

ORDER = BLS12_381_SCALAR_ORDER
if curve.curve_order != ORDER:
    raise RuntimeError('Pairing scalar field mismatch')


def _encode(point, group):
    if group == 1:
        return int(compress_G1(point)).to_bytes(48, 'big')
    a, b = compress_G2(point)
    return int(a).to_bytes(48, 'big') + int(b).to_bytes(48, 'big')


def _decode(data, group):
    length = 48 if group == 1 else 96
    if type(data) is not bytes or len(data) != length:
        raise ValueError('Invalid compressed group encoding length')
    try:
        point = (decompress_G1(int.from_bytes(data, 'big')) if group == 1 else
                 decompress_G2((int.from_bytes(data[:48], 'big'), int.from_bytes(data[48:], 'big'))))
        if not curve.is_inf(curve.multiply(point, ORDER)):
            raise ValueError('Point is outside the prime-order subgroup')
        if _encode(point, group) != data:
            raise ValueError('Noncanonical group encoding')
        return point
    except (ValueError, TypeError, AssertionError, OverflowError) as exc:
        raise ValueError('Invalid group element') from exc


def generator(group: int) -> bytes:
    _check_group(group)
    return _encode(curve.G1 if group == 1 else curve.G2, group)


def identity(group: int) -> bytes:
    _check_group(group)
    return _encode(curve.Z1 if group == 1 else curve.Z2, group)


def _check_group(group):
    if type(group) is not int or group not in (1, 2):
        raise ValueError('Expected group 1 or 2')


def validate(data: bytes, group: int) -> None:
    _check_group(group)
    _decode(data, group)


def add(a: bytes, b: bytes, group: int) -> bytes:
    _check_group(group)
    return _encode(curve.add(_decode(a, group), _decode(b, group)), group)


def multiply(point: bytes, scalar: int, group: int) -> bytes:
    _check_group(group)
    if type(scalar) is not int:
        raise TypeError('Scalar must be an integer')
    return _encode(curve.multiply(_decode(point, group), scalar % ORDER), group)


def pairing_equal(a: bytes, b: bytes, c: bytes, d: bytes) -> bool:
    """Check e(a,b)=e(c,d); mathematical argument order is G1,G2."""
    ap, bp, cp, dp = _decode(a, 1), _decode(b, 2), _decode(c, 1), _decode(d, 2)
    product = curve.pairing(bp, ap, final_exponentiate=False)
    product *= curve.pairing(dp, curve.neg(cp), final_exponentiate=False)
    return curve.final_exponentiate(product) == curve.FQ12.one()
