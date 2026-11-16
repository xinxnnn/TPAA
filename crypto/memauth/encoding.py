"""Canonical typed encodings for local MemAuth primitive interfaces.

The paper leaves byte encodings abstract. These encodings are an explicit
engineering convention, not an implicit definition of H0/H1 or protocol fields.
"""
import hashlib


def _frame(tag: bytes, payload: bytes) -> bytes:
    if len(tag) > 255 or len(payload) >= 2**64:
        raise ValueError('Encoding component too large')
    return b'MA1' + bytes((len(tag),)) + tag + len(payload).to_bytes(8, 'big') + payload


def encode_value(value) -> bytes:
    if type(value) is bytes:
        return _frame(b'bytes', value)
    if type(value) is str:
        return _frame(b'utf8', value.encode('utf-8'))
    if type(value) is int:
        if value < 0:
            raise ValueError('Integers must be nonnegative')
        size = max(1, (value.bit_length() + 7) // 8)
        payload = value.to_bytes(size, 'big')
        return _frame(b'uint', payload)
    if type(value) in (tuple, list):
        encoded = [encode_value(item) for item in value]
        return _frame(b'list', len(encoded).to_bytes(8, 'big') + b''.join(
            len(item).to_bytes(8, 'big') + item for item in encoded))
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise TypeError('Map keys must be strings')
        entries = []
        for key in sorted(value):
            k, v = encode_value(key), encode_value(value[key])
            entries.append(len(k).to_bytes(8, 'big') + k + len(v).to_bytes(8, 'big') + v)
        return _frame(b'map', len(entries).to_bytes(8, 'big') + b''.join(entries))
    raise TypeError('Unsupported encoded value type')


def hash_to_field(domain: str, value, q: int) -> int:
    if type(domain) is not str or not domain:
        raise ValueError('Hash domain is required')
    if type(q) is not int or not 2 <= q < 2**256:
        raise ValueError('Expected order between 2 and 2^256-1 for SHA-256 sampling')
    # Rejection sampling avoids modular bias; separate counter is unambiguous.
    width = (q.bit_length() + 7) // 8
    excess = width * 8 - q.bit_length()
    for counter in range(2**32):
        digest = hashlib.sha256(_frame(b'hash-to-field', encode_value((domain, value, counter)))).digest()
        candidate = int.from_bytes(digest[:width], 'big') >> excess
        if candidate < q:
            return candidate
    raise RuntimeError('Hash-to-field rejection limit exceeded')
