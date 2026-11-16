"""Keep unfinished enrollment disabled until role isolation is implemented."""

import unittest

from services.shared.memauth_service import EnrollmentUnavailable, require_trusted_module


class EnrollmentBoundaryTests(unittest.TestCase):
    def test_enrollment_fails_closed_without_independent_roles(self):
        with self.assertRaisesRegex(EnrollmentUnavailable, "independent PA module"):
            require_trusted_module()


if __name__ == "__main__":
    unittest.main()
