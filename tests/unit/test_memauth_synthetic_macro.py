import unittest

try:
    import py_ecc
    from Crypto.Hash import keccak
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import chameleon as ch
    from crypto.memauth.synthetic_macro import construct, append


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class MacroTests(unittest.TestCase):
    def test_append_retains_point_and_ch_commitment(self):
        keys = ch.keygen()
        events = [('t1', 'read', 'document', 'pa', 'tool')]
        old = construct('macro:a', 't1', 'did:pa:synthetic', events, keys.public, randomness=42)
        new = append(old, [('t2', 'write', 'document', 'pa', 'tool')], keys.secret)
        self.assertNotEqual(old.root, new.root)
        self.assertEqual(old.ch_root, new.ch_root)
        self.assertEqual(old.point, new.point)
        self.assertEqual(len(new.digests), 2)
        self.assertEqual(len(old.digests), 1)
        with self.assertRaises(ValueError):
            append(old, events, (keys.secret + 1) % ch.backend.ORDER)


if __name__ == '__main__':
    unittest.main()
