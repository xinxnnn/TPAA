import json
from pathlib import Path
import tempfile
import unittest

try:
    import py_ecc
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth.vault import PASecrets, seal, unseal, save_new, load


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class VaultTests(unittest.TestCase):
    def test_unlock_restart_and_no_secret_fields(self):
        material = PASecrets(123456789, 987654321)
        blob = seal(material, 'separate synthetic unlock password')
        self.assertEqual(unseal(blob, 'separate synthetic unlock password'), material)
        self.assertNotIn(b'123456789', blob)
        self.assertNotIn(b'987654321', blob)
        self.assertNotIn(b'sUser', blob)
        self.assertNotIn(b'theta', blob)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vault.json'
            save_new(path, material, 'unlock')
            self.assertEqual(load(path, 'unlock'), material)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                save_new(path, PASecrets(7, 8), 'another unlock')
            self.assertEqual(path.read_bytes(), before)

    def test_wrong_password_tampering_and_bounded_kdf(self):
        blob = seal(PASecrets(7, 8), 'unlock')
        with self.assertRaises(ValueError):
            unseal(blob, 'wrong')
        for name, value in (('n', 2**30), ('ciphertext', 'AAAA'), ('extra', 'sUser')):
            data = json.loads(blob)
            data[name] = value
            with self.assertRaises(ValueError):
                unseal(json.dumps(data).encode(), 'unlock')
        with self.assertRaises(ValueError):
            unseal(b'x' * 4097, 'unlock')


if __name__ == '__main__':
    unittest.main()
