import unittest

try:
    import py_ecc
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import accountability_experiment as a, pairing_backend as b, ps
    from crypto.memauth import executable_profile as p
    from crypto.memauth.issuance_experiment import Registration


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class AccountabilityTests(unittest.TestCase):
    def test_unblind_lookup_and_joint_unmask(self):
        issuer, n = ps.SecretKey(3, 5), 11413
        anchor = b.multiply(b.generator(1), 13, 1)
        gamma = p.h1(p.prf(3, ('did:tp:test', p.scalar_bytes(5)), n), 'did:sa:test')
        blinded = b.multiply(anchor, gamma, 1)
        recovered = a.unblind(issuer, 'did:tp:test', 'did:sa:test', n, blinded)
        self.assertEqual(recovered, anchor)
        record = Registration(anchor, 'did:pa:test', 123, b'af')
        self.assertIs(a.locate(recovered, (record,)), record)
        self.assertIsNone(a.locate(b.generator(1), (record,)))
        share = a.ap_share(17, 'did:ap:test', b'af', n)
        link = a.finish(record, (73+share) % n, share, n, frozenset({73}))
        self.assertEqual(link.identity_hash, 73)
        self.assertIsNone(a.finish(record, (73+share) % n, (share+1) % n, n, frozenset({73})))
        with self.assertRaises(ValueError):
            a.locate(anchor, (record, record))


if __name__ == '__main__':
    unittest.main()
