"""Hash and trapdoor-hash properties for public synthetic test data."""
import unittest

try:
    import py_ecc  # noqa: F401
    from Crypto.Hash import keccak  # noqa: F401
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import chameleon as ch
    from crypto.memauth.encoding import encode_value, hash_to_field
    from crypto.memauth.experiment_profiles import keccak_typed_duplicate_last
    from crypto.memauth.merkle import MerkleTree, Parameters, UndefinedPaperRule
    from crypto.memauth.pairing_backend import ORDER

    def test_h0(message):
        return hash_to_field('synthetic-ch-test-only', message, ORDER)


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class MerkleChameleonTests(unittest.TestCase):
    def test_typed_encoding_separates_types_and_boundaries(self):
        self.assertNotEqual(encode_value('ab'), encode_value(b'ab'))
        self.assertNotEqual(encode_value(('ab', 'c')), encode_value(('a', 'bc')))
        self.assertEqual(encode_value({'a': 1, 'b': 2}), encode_value({'b': 2, 'a': 1}))
        with self.assertRaises(ValueError):
            encode_value(-1)
        self.assertLess(hash_to_field('test', 'value', 101), 101)
        self.assertNotEqual(hash_to_field('a', 'value', 2**255), hash_to_field('b', 'value', 2**255))

    def test_merkle_membership_order_and_odd_width(self):
        parameters = keccak_typed_duplicate_last()
        for leaves in ([b'a'], [b'a', b'b'], [b'a', b'b', b'c'], [b'a', b'b', b'c', b'd', b'e']):
            tree = MerkleTree(leaves, parameters=parameters)
            for i, leaf in enumerate(leaves):
                self.assertTrue(MerkleTree.verify(leaf, tree.inclusion_proof(i), tree.root, parameters=parameters))
                self.assertFalse(MerkleTree.verify(b'altered', tree.inclusion_proof(i), tree.root, parameters=parameters))
            if len(leaves) > 1:
                self.assertNotEqual(tree.root, MerkleTree(list(reversed(leaves)), parameters=parameters).root)
        with self.assertRaises(ValueError):
            MerkleTree([], parameters=parameters)
        with self.assertRaises(IndexError):
            MerkleTree([1], parameters=parameters).inclusion_proof(1)

    def test_undefined_merkle_rules_stop(self):
        with self.assertRaises(UndefinedPaperRule):
            MerkleTree([b'a'])
        experiment = keccak_typed_duplicate_last()
        abstract = Parameters(experiment.hash_bytes, experiment.encode_leaf, 32)
        with self.assertRaises(UndefinedPaperRule):
            MerkleTree([1, 2, 3], parameters=abstract)
        # Even leaf counts can still reach an undefined odd-width inner level.
        with self.assertRaises(UndefinedPaperRule):
            MerkleTree(list(range(6)), parameters=abstract)
        tree = MerkleTree([1, 2, 3], parameters=experiment)
        with self.assertRaises(UndefinedPaperRule):
            MerkleTree.verify(1, tree.inclusion_proof(0), tree.root, parameters=abstract)

    def test_hash_sampling_rejects_unsupported_width(self):
        with self.assertRaises(ValueError):
            hash_to_field('test', 1, 2**300)

    def test_chameleon_adaptation_matches_paper_formula(self):
        keys = ch.keygen()
        old_message, new_message, rho = b'old root', b'new root', 42
        rho_new = ch.adapt(keys.secret, old_message, rho, new_message, h0=test_h0)
        old_hash = ch.generate(keys.public, old_message, rho, h0=test_h0)
        self.assertEqual(old_hash, ch.generate(keys.public, new_message, rho_new, h0=test_h0))
        self.assertTrue(ch.verify_collision(keys.public, old_message, rho, new_message, rho_new, h0=test_h0))
        self.assertFalse(ch.verify_collision(keys.public, old_message, rho, new_message, rho_new+1, h0=test_h0))
        self.assertEqual(ch.adapt(keys.secret, old_message, rho, old_message, h0=test_h0), rho)

    def test_chameleon_rejects_invalid_secret_and_public_key(self):
        with self.assertRaises(ValueError):
            ch.adapt(0, b'a', 1, b'b', h0=test_h0)
        with self.assertRaises(ValueError):
            ch.generate(bytes(48), b'a', 1, h0=test_h0)


if __name__ == '__main__':
    unittest.main()
