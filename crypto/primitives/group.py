"""secp256k1 群运算 —— 恒定时间实现。

为什么不用朴素的 double-and-add：
    朴素实现的分支取决于私钥比特，执行时间随比特序列变化，
    可通过计时侧信道恢复私钥。这里用 Montgomery ladder，
    两条分支都算出来再做常数时间选择，执行路径与秘密比特无关。

坐标：Jacobian (X, Y, Z)，满足 Y² = X³ + 7·Z⁶，
避免每步做模逆（模逆代价高且实现分支多、易泄漏）。

依赖：只用标准库（hashlib / secrets），便于审计与移植。
"""

from __future__ import annotations

from secrets import randbelow

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Jacobian 点 (X, Y, Z)；None 表示无穷远点 O
Point = tuple[int, int, int] | None

G: Point = (GX, GY, 1)


# ---------------------------------------------------------------------------
# Jacobian 点运算
# ---------------------------------------------------------------------------


def _jac_double(p: Point) -> Point:
    if p is None:
        return None
    x, y, z = p
    if y % P == 0 or z % P == 0:
        return None
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P                       # a = 0，故 M = 3X²
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * yy * yy) % P
    nz = 2 * y * z % P
    return (nx, ny, nz)


def _jac_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 % P * z2z2 % P
    s2 = y2 * z1 % P * z1z1 % P
    if u1 == u2:
        if s1 != s2:
            return None                          # P + (−P) = O
        return _jac_double(p1)
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    hh = h * h % P
    hhh = hh * h % P
    nx = (r * r - hhh - 2 * u1 * hh) % P
    ny = (r * (u1 * hh - nx) - s1 * hhh) % P
    nz = h * z1 % P * z2 % P
    return (nx, ny, nz)


def _cselect(bit: int, a: int, b: int) -> int:
    """常数时间选择：bit=1 返回 a，bit=0 返回 b。"""
    mask = -bit
    return b ^ (mask & (a ^ b))


def _cselect_point(bit: int, p1: Point, p2: Point) -> Point:
    if p1 is None and p2 is None:
        return None
    if p1 is None:
        return p2 if bit == 0 else None
    if p2 is None:
        return None if bit == 0 else p1
    return tuple(_cselect(bit, p1[i], p2[i]) for i in range(3))


def _to_affine(p: Point) -> Point:
    if p is None:
        return None
    x, y, z = p
    if z % P == 0:
        return None
    zinv = pow(z, P - 2, P)
    zinv2 = zinv * zinv % P
    zinv3 = zinv2 * zinv % P
    return (x * zinv2 % P, y * zinv3 % P, 1)


# ---------------------------------------------------------------------------
# 对外接口
# ---------------------------------------------------------------------------


def point_mul(k: int, pt: Point = G) -> Point:
    """恒定时间标量乘法（Montgomery ladder）。"""
    if pt is None:
        return None
    k %= N
    if k == 0:
        return None

    r0: Point = None
    r1: Point = pt

    for i in range(255, -1, -1):
        bit = (k >> i) & 1

        # bit=1: R0' = R0+R1 , R1' = 2·R1
        # bit=0: R1' = R0+R1 , R0' = 2·R0
        # 两条分支都算，再用常数时间选择 —— 不因秘密比特走不同分支
        s = _jac_add(r0, r1)
        d0 = _jac_double(r0)
        d1 = _jac_double(r1)

        r0 = _cselect_point(bit, s, d0)
        r1 = _cselect_point(bit, d1, s)

    return _to_affine(r0)


def point_add(p1: Point, p2: Point) -> Point:
    """对外加法：结果归一化到仿射坐标，便于直接比较。"""
    return _to_affine(_jac_add(p1, p2))


def point_neg(p: Point) -> Point:
    if p is None:
        return None
    return (p[0], (-p[1]) % P, p[2])


def pubkey(sk: int) -> Point:
    """由私钥标量导出公钥点 pk = sk·G。"""
    return point_mul(sk % N)


def new_secret() -> int:
    return randbelow(N - 1) + 1


def ser_point(pt: Point) -> bytes:
    """序列化为 33 字节压缩格式。"""
    if pt is None:
        return b"\x00" * 33
    x, y, _ = _to_affine(pt)
    prefix = b"\x02" if (y & 1) == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def deser_point(data: bytes) -> Point:
    """`ser_point` 的逆运算：33 字节压缩格式 → 仿射点。

    ★ 必须校验"点在曲线上"。不校验的话，攻击者可以塞一个不在曲线上的点进来，
      让它参与点运算，从而把群律拖进小群 / 奇异曲线的语义里 ——
      公开参数一律当作不可信输入对待，这一步不能省。
    """
    if len(data) != 33:
        raise ValueError(f"压缩点必须是 33 字节，实际 {len(data)}")
    prefix = data[0]
    if prefix not in (0x02, 0x03):
        raise ValueError(f"压缩点前缀非法：0x{prefix:02x}")
    x = int.from_bytes(data[1:], "big")
    if x >= P:
        raise ValueError("点坐标越界")
    y_sq = (pow(x, 3, P) + B * pow(1, 6, P)) % P
    y = pow(y_sq, (P + 1) // 4, P)          # P ≡ 3 (mod 4)，直接开方
    if y * y % P != y_sq:
        raise ValueError("该 x 不在曲线方程上")
    if (y & 1) != (prefix & 1):
        y = P - y
    pt: Point = (x, y, 1)
    if is_on_curve(pt) is False:            # 二次确认，防止上面的推导有疏漏
        raise ValueError("解出的点不在曲线上")
    return pt


def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y, z = pt
    lhs = y * y % P
    rhs = (pow(x, 3, P) + B * pow(z, 6, P)) % P
    return lhs == rhs
