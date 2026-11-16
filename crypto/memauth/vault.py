"""Password-unlocked experimental PA vault; not a paper protocol message.

Software isolation only. The caller supplies a dedicated unlock password,
distinct from sUser. Neither password, sUser, nor theta is an accepted field.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile

from Crypto.Cipher import AES

from . import pairing_backend as b

_FORMAT = 'memauth-local-pa-vault-v1'
_N, _R, _P = 2**15, 8, 1


@dataclass(frozen=True)
class PASecrets:
    sk_pa: int = field(repr=False)
    rho0: int = field(repr=False)

    def __post_init__(self):
        if type(self.sk_pa) is not int or not 0 < self.sk_pa < b.ORDER:
            raise ValueError('PA key must be in Fq*')
        if type(self.rho0) is not int or not 0 <= self.rho0 < b.ORDER:
            raise ValueError('Initial randomness must be in Fq')


def _key(password: str, salt: bytes) -> bytes:
    if type(password) is not str or not password:
        raise ValueError('Dedicated experimental unlock password required')
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=_N, r=_R, p=_P,
                          maxmem=128 * 1024 * 1024, dklen=32)


def _b64(value):
    return base64.b64encode(value).decode('ascii')


def seal(material: PASecrets, password: str) -> bytes:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = {'format': _FORMAT, 'kdf': 'scrypt', 'n': _N, 'r': _R, 'p': _P,
              'salt': _b64(salt), 'cipher': 'AES-256-GCM', 'nonce': _b64(nonce)}
    aad = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('ascii')
    cipher = AES.new(_key(password, salt), AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    # Explicit allowlist prevents arbitrary application secrets from being serialized.
    plaintext = json.dumps({'sk_pa': str(material.sk_pa), 'rho0': str(material.rho0)},
                           separators=(',', ':')).encode('ascii')
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return json.dumps(dict(header, ciphertext=_b64(ciphertext), tag=_b64(tag)),
                      sort_keys=True, separators=(',', ':')).encode('ascii')


def unseal(blob: bytes, password: str) -> PASecrets:
    if type(blob) is not bytes or len(blob) > 4096:
        raise ValueError('Invalid PA vault size')
    try:
        document = json.loads(blob)
        expected = {'format', 'kdf', 'n', 'r', 'p', 'salt', 'cipher', 'nonce', 'ciphertext', 'tag'}
        if type(document) is not dict or set(document) != expected:
            raise ValueError('Unknown PA vault fields')
        if (document['format'], document['kdf'], document['n'], document['r'], document['p'],
                document['cipher']) != (_FORMAT, 'scrypt', _N, _R, _P, 'AES-256-GCM'):
            raise ValueError('Unsupported PA vault parameters')
        decode = lambda name: base64.b64decode(document[name], validate=True)
        salt, nonce, tag, ciphertext = (decode(name) for name in ('salt', 'nonce', 'tag', 'ciphertext'))
        if len(salt) != 16 or len(nonce) != 12 or len(tag) != 16:
            raise ValueError('Invalid PA vault parameters')
        header = {k: v for k, v in document.items() if k not in ('ciphertext', 'tag')}
        aad = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('ascii')
        cipher = AES.new(_key(password, salt), AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(aad)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        values = json.loads(plaintext)
        if set(values) != {'sk_pa', 'rho0'} or any(type(v) is not str for v in values.values()):
            raise ValueError('Unknown PA secret fields')
        return PASecrets(int(values['sk_pa']), int(values['rho0']))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise ValueError('PA vault unlock failed or artifact invalid') from exc


def save_new(path: Path, material: PASecrets, password: str) -> None:
    """Create once. No implicit recovery, overwrite, or password persistence."""
    blob = seal(material, password)
    path = Path(path)
    # A temporary sibling is populated before atomically publishing via hard link.
    # No fallback to nonexclusive replacement: an existing vault must survive.
    descriptor, temporary = tempfile.mkstemp(prefix='.memauth-vault-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def load(path: Path, password: str) -> PASecrets:
    with Path(path).open('rb') as stream:
        return unseal(stream.read(4097), password)
