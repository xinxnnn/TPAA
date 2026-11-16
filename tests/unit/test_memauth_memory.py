"""Phase 1 arithmetic/state integrity tests, not full credential authorization."""
import unittest
from dataclasses import replace

try:
    import py_ecc
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import pairing_backend as b
    from crypto.memauth.memory import (
        MacroPoint, build, create, validate, append_polynomial_state, synchronization_witness,
    )
    from crypto.memauth.srs import SRS


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class MemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srs = SRS(tuple(b.multiply(b.generator(1), 7**i, 1) for i in range(7)),
                      tuple(b.multiply(b.generator(2), 7**i, 2) for i in range(7)))

    def initial(self):
        return build(self.srs, 13, MacroPoint(2, 31), MacroPoint(3, 46))

    def test_build_create_and_sync(self):
        initial = self.initial()
        self.assertEqual(initial.polynomial.coefficients, (13, 5, 2))
        updated = create(self.srs, initial, [MacroPoint(4, 88)], theta=9)
        self.assertEqual(updated.polynomial(9), initial.polynomial(9))
        self.assertEqual(updated.polynomial(4), 88)
        self.assertEqual(updated.anchor, initial.anchor)
        self.assertNotEqual(updated.commitment, initial.commitment)
        self.assertIs(append_polynomial_state(self.srs, updated), updated)
        # Independent phi(7)=7*(7-2)*(7-3)=140.
        self.assertEqual(synchronization_witness(self.srs, initial),
                         b.multiply(b.generator(2), 140, 2))
        self.assertNotIn('theta', updated.__dataclass_fields__)

    def test_reject_corruption_and_collision(self):
        state = self.initial()
        for bad in (replace(state, commitment=b.generator(1)),
                    replace(state, srs_id='wrong'),
                    replace(state, points=state.points[:-1] + (MacroPoint(3, 47),))):
            with self.assertRaises(ValueError):
                validate(self.srs, bad)
        for points, theta in (([MacroPoint(2, 1)], 9), ([MacroPoint(9, 1)], 9)):
            with self.assertRaises(ValueError):
                create(self.srs, state, points, theta=theta)
        self.assertEqual(state.polynomial.coefficients, (13, 5, 2))

    def test_wrong_authorization_and_degree_do_not_mutate(self):
        initial = self.initial()
        updated = create(self.srs, initial, [MacroPoint(4, 88)], theta=9)
        with self.assertRaises(ValueError):
            create(self.srs, updated, [MacroPoint(5, 17)], theta=10)
        with self.assertRaises(ValueError):
            create(self.srs, initial, [MacroPoint(x, 1) for x in (4, 5, 6, 8)], theta=9)
        # Repeated updates retain the original authorization anchor.
        later = create(self.srs, updated, [MacroPoint(5, 17)], theta=9)
        self.assertEqual(later.polynomial.degree, 5)
        self.assertEqual(initial.polynomial.degree, 2)


if __name__ == '__main__':
    unittest.main()
