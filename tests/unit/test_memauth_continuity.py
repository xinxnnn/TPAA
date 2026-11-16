import unittest
from dataclasses import replace

try:
    import py_ecc
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import pairing_backend as b
    from crypto.memauth.continuity_primitives import prove, verify_equations
    from crypto.memauth.memory import MacroPoint, build, create, synchronization_witness
    from crypto.memauth.srs import SRS


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class ContinuityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srs = SRS(tuple(b.multiply(b.generator(1), 7**i, 1) for i in range(6)),
                      tuple(b.multiply(b.generator(2), 7**i, 2) for i in range(6)))

    def test_two_equations_and_tampering_against_fixed_snapshot(self):
        old = build(self.srs, 13, MacroPoint(2, 31), MacroPoint(3, 46))
        current = create(self.srs, old, [MacroPoint(4, 88)], theta=9)
        proof = prove(self.srs, old, current, 2, 11)
        cp_old = b.multiply(old.commitment, 11, 1)
        witness = synchronization_witness(self.srs, old)
        k1 = b.multiply(b.generator(1), 11, 1)
        def verify(p=proof, y=31):
            return verify_equations(self.srs, cp_old, witness, k1, 2, y, p)
        self.assertTrue(all(verify().values()))
        self.assertFalse(verify(y=32)['openingEquation'])
        altered = replace(proof, update=b.add(proof.update, b.generator(1), 1))
        self.assertFalse(verify(altered)['updateEquation'])
        unchanged = prove(self.srs, old, old, 2, 11)
        self.assertEqual(unchanged.update, b.identity(1))
        self.assertTrue(all(verify(unchanged).values()))
        self.assertEqual(old.polynomial.coefficients, (13, 5, 2))
        with self.assertRaises(ValueError):
            prove(self.srs, old, current, 4, 11)


if __name__ == '__main__':
    unittest.main()
