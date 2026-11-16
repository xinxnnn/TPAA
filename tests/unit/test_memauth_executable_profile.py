import unittest

from crypto.memauth import executable_profile as profile


class ProfileTests(unittest.TestCase):
    def test_domains_canonical_scalars_and_large_modulus(self):
        self.assertEqual(len(profile.scalar_bytes(7)), 32)
        self.assertEqual(profile.h1('a', 'bc'), profile.h1('a', 'bc'))
        self.assertNotEqual(profile.h1('a', 'bc'), profile.h1('ab', 'c'))
        self.assertNotEqual(profile.h0((1, 2)), profile.h2((1, 2)))
        self.assertTrue(0 < profile.kdf(7, 'did:sa:test') < profile.ORDER)
        modulus = 2**2048 - 159
        result = profile.prf(7, ('did:tp:test', profile.scalar_bytes(9)), modulus)
        self.assertTrue(0 <= result < modulus)
        self.assertEqual(result, profile.prf(7, ('did:tp:test', profile.scalar_bytes(9)), modulus))
        self.assertFalse(profile.manifest()['baselineDefault'])


if __name__ == '__main__':
    unittest.main()
