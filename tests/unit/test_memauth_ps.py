"""PS and PHC equations checked against real pairings and independent vectors."""
import unittest

try:
    import py_ecc
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import pairing_backend as b
    from crypto.memauth import ps


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class PSTests(unittest.TestCase):
    def setUp(self):
        self.secret = ps.SecretKey(3, 5)
        self.public = self.secret.public_key()

    def test_independent_vector_and_tampering(self):
        signature = ps.sign(self.secret, 7, randomizer=11)
        self.assertEqual(signature.first, b.multiply(b.generator(1), 11, 1))
        self.assertEqual(signature.second, b.multiply(b.generator(1), 418, 1))
        self.assertTrue(ps.verify(self.public, 7, signature))
        self.assertFalse(ps.verify(self.public, 8, signature))
        self.assertFalse(ps.verify(ps.SecretKey(4, 5).public_key(), 7, signature))
        self.assertFalse(ps.verify(self.public, 7, ps.Signature(
            signature.first, b.add(signature.second, b.generator(1), 1))))

    def test_rerandomization(self):
        signature = ps.sign(self.secret, 7, randomizer=11)
        randomized = ps.rerandomize(signature, randomizer=13)
        self.assertNotEqual(signature, randomized)
        self.assertEqual(randomized.first, b.multiply(b.generator(1), 143, 1))
        self.assertTrue(ps.verify(self.public, 7, randomized))
        self.assertFalse(ps.verify(self.public, 8, randomized))

    def test_identity_and_bad_encodings(self):
        identity = ps.Signature(b.identity(1), b.identity(1))
        self.assertFalse(ps.verify(self.public, 7, identity))
        with self.assertRaises(ValueError):
            ps.rerandomize(identity)
        with self.assertRaises(ValueError):
            ps.verify(self.public, 7, ps.Signature(b'bad', b.generator(1)))
        with self.assertRaises(ValueError):
            ps.PublicKey(b'bad', self.public.y)
        for value in (0, b.ORDER, -1, True):
            with self.assertRaises(ValueError):
                ps.sign(self.secret, 7, randomizer=value)

    def test_fixed_base_phc_equation_is_separate(self):
        delta = ps.sign_phc_scalar(self.secret, 7)
        self.assertEqual(delta, b.multiply(b.generator(1), 38, 1))
        self.assertTrue(ps.verify_phc_scalar(self.public, 7, delta))
        self.assertFalse(ps.verify_phc_scalar(self.public, 8, delta))
        randomized = ps.rerandomize(ps.Signature(b.generator(1), delta), randomizer=13)
        self.assertTrue(ps.verify(self.public, 7, randomized))
        with self.assertRaises(ValueError):
            ps.sign_phc_scalar(ps.SecretKey(0, 5), 7)

    def test_original_scalar_domains_preserved(self):
        # General PS includes zero x/y; do not apply Phase 0's nonzero rule to III.B.
        zero = ps.SecretKey(0, 0)
        self.assertTrue(ps.verify(zero.public_key(), 0, ps.sign(zero, 0, randomizer=1)))
        # A valid signature's second component can be the identity.
        message = (-3 * pow(5, -1, b.ORDER)) % b.ORDER
        signature = ps.sign(self.secret, message, randomizer=11)
        self.assertEqual(signature.second, b.identity(1))
        self.assertTrue(ps.verify(self.public, message, signature))

    def test_fixed_base_two_credential_diagnostic(self):
        # Diagnostic of Phase 0's printed fixed base, NOT general randomized PS.
        # Two known messages 7,8 allow extrapolation delta(9)=2*delta(8)-delta(7).
        first = ps.sign_phc_scalar(self.secret, 7)
        second = ps.sign_phc_scalar(self.secret, 8)
        forged = b.add(b.multiply(second, 2, 1), b.multiply(first, -1, 1), 1)
        self.assertTrue(ps.verify_phc_scalar(self.public, 9, forged))
        self.assertEqual(forged, ps.sign_phc_scalar(self.secret, 9))


if __name__ == '__main__':
    unittest.main()
