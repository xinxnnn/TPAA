import unittest
from dataclasses import replace

try:
    import py_ecc
    from Crypto.Hash import keccak
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import pairing_backend as b, ps
    from crypto.memauth.audit_events import APConstructPublic, TPFinalizePublic, observe, initial_memory
    from crypto.memauth.srs import SRS


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class AuditTests(unittest.TestCase):
    def test_explicit_projection_and_actual_signature_output(self):
        secret = ps.SecretKey(3, 5)
        delta = ps.sign_phc_scalar(secret, 13)
        public = b.multiply(b.generator(1), 7, 1)
        event = observe('2026-11-10T12:00:00+08:00', 'did:tp:synthetic', TPFinalizePublic(public, delta))
        self.assertEqual(event.source_fields, ('PK_PA', 'delta_TP'))
        self.assertIn(delta.hex(), event.public_trace()['publicProjectionEncodingHex'])
        self.assertNotIn('KTP', str(event.public_trace()))
        with self.assertRaises(TypeError):
            observe('t', 'did:tp:test', {'PK_PA': public, 'sUser': 'secret'})
        self.assertNotEqual(event.object_digest,
                            observe('t', 'did:tp:test', TPFinalizePublic(public, b.generator(1))).object_digest)

    def test_initial_sequence_build_and_tamper_rejection(self):
        srs = SRS(tuple(b.multiply(b.generator(1), 7**i, 1) for i in range(4)),
                  tuple(b.multiply(b.generator(2), 7**i, 2) for i in range(4)))
        public = b.multiply(b.generator(1), 11, 1)
        tp = observe('t1', 'did:tp:test', TPFinalizePublic(public, ps.sign_phc_scalar(ps.SecretKey(3, 5), 13)))
        # Caller-provided synthetic ciphertext fixture; no identity issuance is claimed.
        ap = observe('t2', 'did:ap:test', APConstructPublic(1234567))
        state, first, second = initial_memory(srs, 13, 'did:pa:test', public, tp, ap, tp_rho=17, ap_rho=19)
        self.assertEqual(first.digests, (tp.event_digest,))
        self.assertEqual(second.digests, (ap.event_digest,))
        self.assertEqual(state.polynomial(0), 13)
        with self.assertRaises(ValueError):
            initial_memory(srs, 13, 'did:pa:test', public, replace(tp, object_digest='changed'), ap,
                           tp_rho=17, ap_rho=19)
        with self.assertRaises(ValueError):
            initial_memory(srs, 13, 'did:pa:test', b.generator(1), tp, ap, tp_rho=17, ap_rho=19)
        with self.assertRaises(ValueError):
            initial_memory(srs, 13, 'did:pa:test', public, replace(tp, source_fields=('KTP',)), ap,
                           tp_rho=17, ap_rho=19)


if __name__ == '__main__':
    unittest.main()
