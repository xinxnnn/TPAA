"""Real pairing checks; known-alpha fixtures are synthetic test data only."""
import unittest

try:
    import py_ecc
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import pairing_backend as b
    from crypto.memauth.kzg import open_at, verify
    from crypto.memauth.polynomial import Polynomial
    from crypto.memauth.srs import SRS


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class KZGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Never use this publicly known trapdoor setup for real credentials.
        cls.srs = SRS(
            tuple(b.multiply(b.generator(1), 7**i, 1) for i in range(4)),
            tuple(b.multiply(b.generator(2), 7**i, 2) for i in range(4)))

    def test_known_commitment_and_proof(self):
        p = Polynomial(b.ORDER, (13, 5, 2))
        commitment = self.srs.commit(p)
        y, proof = open_at(self.srs, p, 3)
        self.assertEqual(y, 46)
        # Independent expected exponents: P(7)=146; Q(X)=11+2X.
        self.assertEqual(commitment, b.multiply(b.generator(1), 146, 1))
        self.assertEqual(proof, b.multiply(b.generator(1), 25, 1))
        self.assertTrue(verify(self.srs, commitment, 3, y, proof))

    def test_tampered_claims(self):
        p = Polynomial(b.ORDER, (13, 5, 2))
        c = self.srs.commit(p)
        y, proof = open_at(self.srs, p, 3)
        self.assertFalse(verify(self.srs, c, 3, y+1, proof))
        self.assertFalse(verify(self.srs, c, 4, y, proof))
        self.assertFalse(verify(self.srs, c, 3, y, b.add(proof, b.generator(1), 1)))
        self.assertFalse(verify(self.srs, b.add(c, b.generator(1), 1), 3, y, proof))

    def test_zero_and_constant(self):
        for value in (0, 19):
            p = Polynomial(b.ORDER, (value,))
            y, proof = open_at(self.srs, p, 8)
            self.assertEqual(proof, b.identity(1))
            self.assertTrue(verify(self.srs, self.srs.commit(p), 8, y, proof))

    def test_reject_invalid_encodings_and_subgroup(self):
        for group in (1, 2):
            for data in (b'', bytes(48 if group == 1 else 96)):
                with self.assertRaises(ValueError):
                    b.validate(data, group)
        # Curve point (0,2) is on G1's curve but outside its prime-order subgroup.
        with self.assertRaises(ValueError):
            b.validate((1 << 383).to_bytes(48, 'big'), 1)
        with self.assertRaises(ValueError):
            verify(self.srs, b'bad', 3, 46, b.generator(1))

    def test_reject_degree_and_field_mismatch(self):
        for operation in (self.srs.commit, lambda p: open_at(self.srs, p, 3)):
            with self.assertRaises(ValueError):
                operation(Polynomial(b.ORDER, (1, 0, 0, 0, 1)))
            with self.assertRaises(ValueError):
                operation(Polynomial(101, (1,)))

    def test_reject_corrupt_srs(self):
        for group in (1, 2):
            g1, g2 = list(self.srs.g1_powers), list(self.srs.g2_powers)
            powers = g1 if group == 1 else g2
            powers[2] = b.multiply(b.generator(group), 50, group)
            with self.assertRaises(ValueError):
                SRS(tuple(g1), tuple(g2))
        with self.assertRaises(ValueError):
            SRS(self.srs.g1_powers, self.srs.g2_powers[:-1])
        with self.assertRaises(ValueError):
            SRS((b.generator(1), b.identity(1)), (b.generator(2), b.identity(2)))

    def test_dual_group_polynomial_relation(self):
        p = Polynomial(b.ORDER, (4, 1, 3))
        self.assertTrue(b.pairing_equal(self.srs.commit(p), b.generator(2),
                                        b.generator(1), self.srs.commit(p, 2)))

    def test_srs_artifact_metadata_rejected(self):
        artifact = self.srs.to_artifact()
        artifact['srsId'] = 'incorrect'
        with self.assertRaises(ValueError):
            SRS.from_artifact(artifact)


if __name__ == '__main__':
    unittest.main()
