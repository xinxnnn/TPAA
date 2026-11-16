"""Public synthetic PS/PHC algebra experiment; no PA credentials are read."""
import json
from time import perf_counter

from crypto.memauth import pairing_backend as b
from crypto.memauth import ps


def build_trace():
    start = perf_counter()
    # Phase 0 c1,c2 are nonzero; sample explicitly for this synthetic issuer.
    import secrets
    key = ps.SecretKey(secrets.randbelow(b.ORDER - 1) + 1,
                       secrets.randbelow(b.ORDER - 1) + 1)
    public = key.public_key()
    message = 7
    signature = ps.sign(key, message)
    randomized = ps.rerandomize(signature)
    delta = ps.sign_phc_scalar(key, message)
    rhs = b.add(public.x, b.multiply(public.y, message, 2), 2)
    return {
        'scope': 'public synthetic algebra only; not issuance, Bootstrap or anonymity proof',
        'sources': ['memauth921.pdf III.B', 'memauth921.pdf Phase 0 PHCFinalize'],
        'backend': 'py-ecc==8.0.0 / BLS12-381',
        'message': str(message),
        'publicKeyG2': {'X': public.x.hex(), 'Y': public.y.hex()},
        'signatureG1': {'first': signature.first.hex(), 'second': signature.second.hex()},
        'rerandomizedG1': {'first': randomized.first.hex(), 'second': randomized.second.hex()},
        'fixedBaseDeltaG1': delta.hex(),
        'formulas': {
            'PS': 'e(sigma1, X+Y*m) = e(sigma2, h); sigma1 != identity',
            'PHC': 'e(delta, h) = e(g, X+Y*y0)',
        },
        'pairingOperands': {
            'psLeftG1': signature.first.hex(), 'psLeftG2': rhs.hex(),
            'psRightG1': signature.second.hex(), 'psRightG2': b.generator(2).hex(),
            'phcLeftG1': delta.hex(), 'phcLeftG2': b.generator(2).hex(),
            'phcRightG1': b.generator(1).hex(), 'phcRightG2': rhs.hex(),
        },
        'verification': {
            'signatureAccepts': ps.verify(public, message, signature),
            'rerandomizedAccepts': ps.verify(public, message, randomized),
            'changedMessageRejected': not ps.verify(public, message + 1, signature),
            'phcEquationAccepts': ps.verify_phc_scalar(public, message, delta),
            'changedY0Rejected': not ps.verify_phc_scalar(public, message + 1, delta),
        },
        'elapsedMs': (perf_counter() - start) * 1000,
    }


if __name__ == '__main__':
    print(json.dumps(build_trace(), indent=2))
