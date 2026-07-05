#!/usr/bin/env python3
"""
Ed25519 -- pure-Python reference implementation (public domain, after D. J.
Bernstein et al.'s ed25519.py), lightly modernized to use stdlib pow() and an
iterative scalar multiply. Zero dependencies.

WHY THIS IS HERE: the rest of the suite is pure-stdlib, and neither `cryptography`
nor `pynacl` is installed. This gives us real asymmetric signatures for
proof-of-possession without a dependency.

NOT PRODUCTION CRYPTO: this is not constant-time and is slow (~ms per op). In a
real deployment swap in libsodium/`cryptography`'s Ed25519 -- the API (keypair /
sign / verify over bytes) is identical, so nothing above this file changes.
"""

import hashlib

_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_B_BITS = 256


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1) % _q
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    k = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k) % _q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k) % _q
    return (x3, y3)


def _scalarmult(P, e: int):
    Q = (0, 1)                     # neutral element
    while e > 0:
        if e & 1:
            Q = _edwards(Q, P)
        P = _edwards(P, P)
        e >>= 1
    return Q


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    return bytes([(y >> (8 * i)) & 0xFF for i in range(_B_BITS // 8)])


def _encodepoint(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(_B_BITS - 1)] + [x & 1]
    return bytes([sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_B_BITS // 8)])


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(_B_BITS))


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(_B_BITS - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, _B_BITS - 1):
        x = _q - x
    P = (x, y)
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _q != 0:
        raise ValueError("point not on curve")
    return P


def _secret_scalar(sk: bytes):
    h = _H(sk)
    a = 2 ** (_B_BITS - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _B_BITS - 2))
    return a, h


def publickey(sk: bytes) -> bytes:
    a, _ = _secret_scalar(sk)
    return _encodepoint(_scalarmult(_B, a))


def signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    a, h = _secret_scalar(sk)
    r = _decodeint_wide(_H(h[_B_BITS // 8: _B_BITS // 4] + m))
    R = _scalarmult(_B, r)
    k = _decodeint_wide(_H(_encodepoint(R) + pk + m))
    S = (r + k * a) % _L
    return _encodepoint(R) + _encodeint(S)


def _decodeint_wide(h: bytes) -> int:
    return sum(2 ** i * _bit(h, i) for i in range(2 * _B_BITS))


def checkvalid(s: bytes, m: bytes, pk: bytes) -> bool:
    if len(s) != _B_BITS // 4 or len(pk) != _B_BITS // 8:
        return False
    try:
        R = _decodepoint(s[:_B_BITS // 8])
        A = _decodepoint(pk)
    except ValueError:
        return False
    S = _decodeint(s[_B_BITS // 8:])
    k = _decodeint_wide(_H(_encodepoint(R) + pk + m))
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, k))


if __name__ == "__main__":
    import os
    sk = os.urandom(32)
    pk = publickey(sk)
    msg = b"proof-of-possession challenge"
    sig = signature(msg, sk, pk)
    print("roundtrip valid:", checkvalid(sig, msg, pk))
    print("rejects tamper :", not checkvalid(sig, b"different", pk))
    other_pk = publickey(os.urandom(32))
    print("rejects wrong pk:", not checkvalid(sig, msg, other_pk))
