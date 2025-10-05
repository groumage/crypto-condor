"""Utils for ECDSA tests."""

import random

from crypto_condor.primitives import ECDSA


def generate_ecdsa_sigs(curve: ECDSA.Curve, algo: ECDSA.Hash, valid: bool) -> str:
    """Generates output data for ECDSA.

    Args:
        curve:
            The elliptic curve to use.
        algo:
            The hash function to use.
        valid:
            Whether the output should be valid signatures or not.

    Returns:
        A string of correctly formatted output.
    """
    all_vectors = ECDSA._load_vectors(ECDSA.VectorType.SIGVER, curve, algo, True, True)

    output = f"# ECDSA output for {str(curve)}\n# {valid = }\n"

    for vectors in all_vectors:
        for test in vectors.tests:
            if valid:
                if test.type != "valid":
                    continue
                output += f"{test.pubkey.hex()}/{test.msg.hex()}/{test.sig.hex()}\n"
            else:
                invalid_sig = random.randbytes(len(test.sig))
                output += f"{test.pubkey.hex()}/{test.msg.hex()}/{invalid_sig.hex()}\n"

    return output
