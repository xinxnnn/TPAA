"""P0 algebra diagnostics only; exponent model, NOT a pairing implementation.

All values are synthetic and public. No production secrets or protocol changes.
Run: python demos/memauth/audit_algebra.py
"""
import json


def run():
    q = 101
    alpha, gamma, y0, slope = 7, 11, 13, 5
    # P(X)=y0+slope*X; represent g^a by a, e(g^a,h^b) by a*b.
    p_alpha = (y0 + slope * alpha) % q
    cp, anchor, pi = gamma * p_alpha % q, gamma * y0 % q, gamma * slope % q
    lhs = (cp - anchor) % q
    literal_rhs = pi * alpha % q  # Visually verified PDF p8: h^alpha.
    standard_rhs = pi * alpha % q
    assert lhs == literal_rhs == standard_rhs

    # Two accepted CREATE transitions reveal a common zero in public coefficients
    # when differences have no other common roots. This tests a disclosure boundary.
    eta, old_x, new_x = 9, 2, 3
    delta1 = lambda x: (x - eta) * x * (x - old_x) % q
    delta2 = lambda x: (x - eta) * x * (x - old_x) * (x - new_x) % q
    roots = [x for x in range(q) if delta1(x) == delta2(x) == 0]
    candidates = [x for x in roots if x not in (0, old_x, new_x)]
    assert candidates == [eta]

    # PPT known-alpha opening forgery, demonstrated in exponent notation.
    commitment, z, fake_y = 23, 4, 77
    forged_pi = (commitment - fake_y) * pow(alpha - z, -1, q) % q
    assert forged_pi * (alpha - z) % q == (commitment - fake_y) % q

    return {
        "model": "synthetic finite-field exponent algebra; not real cryptography",
        "fieldOrder": q,
        "pdf_link_equation": {
            "polynomial": [y0, slope], "alpha": alpha, "gamma": gamma,
            "lhs": lhs, "literalRhs": literal_rhs,
            "literalAccepts": lhs == literal_rhs,
            "rhsWithAlpha": standard_rhs,
            "decision": "PDF p8 visually verified: the printed h^alpha equation holds.",
        },
        "public_polynomial_authorization_point": {
            "commonRoots": roots, "remainingCandidate": candidates,
            "decision": "Review exposure of polynomial coefficients under the stated storage model.",
        },
        "ppt_known_alpha": {
            "commitmentExponent": commitment, "claimedY": fake_y,
            "challenge": z, "forgedProofExponent": forged_pi,
            "pairingEquationAccepts": True,
        },
    }


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
