"""Independent arithmetic constraints, not protocol or pairing tests."""
import unittest

from crypto.memauth.polynomial import (
    BLS12_381_SCALAR_ORDER, Polynomial, interpolate, vanishing,
)


class PolynomialTests(unittest.TestCase):
    def test_interpolation_known_vector(self):
        for q in (101, BLS12_381_SCALAR_ORDER):
            # Independent vector: 13 + 5X + 2X^2.
            p = interpolate(q, [(0, 13), (1, 20), (2, 31)])
            self.assertEqual(p.coefficients, (13, 5, 2))
            self.assertEqual(p(3), 46)

    def test_create_constraints_and_degree(self):
        q = 101
        old = interpolate(q, [(0, 13), (2, 31), (3, 46)])
        theta = 9
        tau = vanishing(q, [theta, 0, 2, 3])
        new_points = [(4, 88), (5, 17)]
        delta = interpolate(q, [(x, (y-old(x))*pow(tau(x), -1, q)) for x, y in new_points])
        updated = old + delta*tau
        for x in (0, 2, 3, theta):
            self.assertEqual(updated(x), old(x))
        for x, y in new_points:
            self.assertEqual(updated(x), y)
        self.assertEqual((updated-old).exact_divide(tau), delta)
        # Node count alone does not bound the actual update degree.
        self.assertEqual(updated.degree, 5)
        with self.assertRaises(ValueError):
            updated.require_degree(4)
        self.assertEqual(updated.require_degree(5), updated)

    def test_rejections(self):
        with self.assertRaises(ValueError):
            interpolate(101, [(1, 2), (102, 3)])
        with self.assertRaises(ValueError):
            interpolate(101, [])
        with self.assertRaises(ValueError):
            Polynomial(15, (1,))
        with self.assertRaises(ValueError):
            Polynomial(101, (1, 1)).exact_divide(Polynomial(101, (0, 1)))
        with self.assertRaises(ZeroDivisionError):
            Polynomial(101, (1,)).divide(Polynomial(101, (0,)))
        with self.assertRaises(ValueError):
            Polynomial(101, (1,)) + Polynomial(103, (1,))

    def test_division_and_zero_normalization(self):
        p = Polynomial(101, (7, 2, 9, 4))
        d = Polynomial(101, (3, 0, 2))
        quotient, remainder = p.divide(d)
        self.assertEqual(quotient*d + remainder, p)
        self.assertLess(remainder.degree, d.degree)
        self.assertEqual(Polynomial(101, (101, 0)).degree, -1)


if __name__ == '__main__':
    unittest.main()
