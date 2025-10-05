"""Module to test ECDSA."""

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from crypto_condor.primitives import ECDSA
from crypto_condor.primitives.common import Console

from ..utils.ecdsa import generate_ecdsa_sigs

console = Console()


@pytest.mark.parametrize(
    ("curve", "algo"),
    [
        # Test a standard combination.
        (ECDSA.Curve.P256, ECDSA.Hash.SHA256),
        # Test another standard combination.
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512),
        # Test a B curve.
        (ECDSA.Curve.B571, ECDSA.Hash.SHA384),
        # Test secp256k1.
        (ECDSA.Curve.SECP256K1, ECDSA.Hash.SHA512),
        # Test Brainpool.
        (ECDSA.Curve.BRAINPOOLP384R1, ECDSA.Hash.SHA384),
        # Test SHA-3.
        (ECDSA.Curve.P521, ECDSA.Hash.SHA3_512),
        # Test a truncated hash.
        (ECDSA.Curve.P384, ECDSA.Hash.SHA512_256),
    ],
)
def test_verify(curve: ECDSA.Curve, algo: ECDSA.Hash):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_verify`.

    The parametrization is not exhaustive, there are simply too many combinations. We
    picked some combinations to cover different cases, more can be added if useful.
    """

    def verify_der(pk: bytes, msg: bytes, sig: bytes) -> bool:
        return ECDSA._verify(pk, algo, msg, sig)

    def verify_pem(pk: bytes, msg: bytes, sig: bytes) -> bool:
        key: ec.EllipticCurvePublicKey = serialization.load_pem_public_key(pk)  # type: ignore
        try:
            key.verify(sig, msg, ec.ECDSA(algo.get_hash_instance()))
            return True
        except InvalidSignature:
            return False

    def verify_point(pk: bytes, msg: bytes, sig: bytes) -> bool:
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            curve.get_curve_instance(), pk
        )
        try:
            key.verify(sig, msg, ec.ECDSA(algo.get_hash_instance()))
            return True
        except InvalidSignature:
            return False

    rd = ECDSA.test_verify(
        verify_der, curve, algo, ECDSA.PubKeyEncoding.DER, resilience=True
    )
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "verify_der failed"

    rd = ECDSA.test_verify(
        verify_pem, curve, algo, ECDSA.PubKeyEncoding.PEM, resilience=True
    )
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "verify_pem failed"

    rd = ECDSA.test_verify(
        verify_point, curve, algo, ECDSA.PubKeyEncoding.UNCOMPRESSED, resilience=True
    )
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "verify_point failed"


@pytest.mark.parametrize(
    ("curve", "algo"),
    [
        # Test a standard combination.
        (ECDSA.Curve.P256, ECDSA.Hash.SHA256),
        # Test another standard combination.
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512),
        # Test a B curve.
        (ECDSA.Curve.B571, ECDSA.Hash.SHA384),
        # Test secp256k1.
        (ECDSA.Curve.SECP256K1, ECDSA.Hash.SHA512),
        # Test Brainpool.
        (ECDSA.Curve.BRAINPOOLP384R1, ECDSA.Hash.SHA384),
        # Test SHA-3.
        (ECDSA.Curve.P521, ECDSA.Hash.SHA3_512),
        # Test a truncated hash.
        (ECDSA.Curve.P384, ECDSA.Hash.SHA512_256),
    ],
)
def test_verify_prehashed(curve: ECDSA.Curve, algo: ECDSA.Hash):
    """Tests :meth:`crypto_condor.primitives.ECDSA.test_verify.

    This test uses pre-hashed messages. It uses the same parametrization as
    :func:`test_verify` but does not cover all types of key encoding. Testing the
    behaviour of pre-hashed messages once should be enough.
    """

    def verify_der(pk: bytes, msg: bytes, sig: bytes) -> bool:
        return ECDSA._verify(pk, algo, msg, sig, pre_hashed=True)

    rd = ECDSA.test_verify(
        verify_der,
        curve,
        algo,
        ECDSA.PubKeyEncoding.DER,
        pre_hashed=True,
        resilience=True,
    )
    console.print_results(rd)
    assert rd.check(fail_if_empty=True)


@pytest.mark.parametrize(
    ("curve", "algo"),
    [
        # Test standard combinations.
        (ECDSA.Curve.P224, ECDSA.Hash.SHA224),
        (ECDSA.Curve.P256, ECDSA.Hash.SHA256),
        (ECDSA.Curve.P384, ECDSA.Hash.SHA384),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512),
        # Test B curves.
        (ECDSA.Curve.B283, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B409, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B571, ECDSA.Hash.SHA512),
        # Test a truncated hash.
        (ECDSA.Curve.P384, ECDSA.Hash.SHA512_256),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512_224),
    ],
)
def test_sign(curve: ECDSA.Curve, algo: ECDSA.Hash):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_sign`.

    The parametrization is not exhaustive, there are simply too many combinations. We
    picked some combinations to cover different cases, more can be added if useful.
    """

    def sign_der(sk: bytes, msg: bytes) -> bytes:
        return ECDSA._sign(sk, algo, msg)

    def sign_pem(sk: bytes, msg: bytes) -> bytes:
        key = serialization.load_pem_private_key(sk, None)
        return key.sign(msg, ec.ECDSA(algo.get_hash_instance()))  # type: ignore

    def sign_value(sk: bytes, msg: bytes) -> bytes:
        key = ec.derive_private_key(
            int.from_bytes(sk, "big"), curve.get_curve_instance()
        )
        return key.sign(msg, ec.ECDSA(algo.get_hash_instance()))

    rd = ECDSA.test_sign(sign_der, curve, algo, ECDSA.KeyEncoding.DER)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "sign_der failed"

    rd = ECDSA.test_sign(sign_pem, curve, algo, ECDSA.KeyEncoding.PEM)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "sign_pem failed"

    rd = ECDSA.test_sign(sign_value, curve, algo, ECDSA.KeyEncoding.INT)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "sign_value failed"


@pytest.mark.parametrize(
    ("curve", "algo"),
    [
        # Test standard combinations.
        (ECDSA.Curve.P224, ECDSA.Hash.SHA224),
        (ECDSA.Curve.P256, ECDSA.Hash.SHA256),
        (ECDSA.Curve.P384, ECDSA.Hash.SHA384),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512),
        # Test B curves.
        (ECDSA.Curve.B283, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B409, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B571, ECDSA.Hash.SHA512),
        # Test a truncated hash.
        (ECDSA.Curve.P384, ECDSA.Hash.SHA512_256),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512_224),
    ],
)
def test_sign_prehashed(curve: ECDSA.Curve, algo: ECDSA.Hash):
    """Tests :meth:`crypto_condor.primitives.ECDSA.test_sign`.

    This test uses pre-hashed messages. It uses the same parametrization as
    :func:`test_sign` but does not cover all types of key encoding. Testing the
    behaviour of pre-hashed messages once should be enough.
    """

    def sign_der_prehashed(sk: bytes, msg: bytes) -> bytes:
        loaded_key = serialization.load_der_private_key(sk, None)
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Loaded key is not an elliptic curve private key.")
        signature = loaded_key.sign(
            msg, ec.ECDSA(utils.Prehashed(algo.get_hash_instance()))
        )
        return signature

    rd = ECDSA.test_sign(
        sign_der_prehashed, curve, algo, ECDSA.KeyEncoding.DER, pre_hashed=True
    )
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "sign_der_prehashed failed"


@pytest.mark.skip(reason="KeyGen arbitrarily fails TestU01")
@pytest.mark.parametrize(
    "curve",
    [
        ECDSA.Curve.P224,
        ECDSA.Curve.P256,
        ECDSA.Curve.P384,
        ECDSA.Curve.P521,
        ECDSA.Curve.B283,
        ECDSA.Curve.B409,
        ECDSA.Curve.B571,
    ],
)
def test_key_pair(curve: ECDSA.Curve):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_key_pair`.

    Uses :mod:`cryptography` to generate the keys.
    """

    def _generate_key_pair() -> tuple[int, int, int]:
        key = ec.generate_private_key(curve.get_curve_instance())
        d = key.private_numbers().private_value
        public_key = key.public_key()
        qx = public_key.public_numbers().x
        qy = public_key.public_numbers().y
        return (d, qx, qy)

    rd = ECDSA.test_key_pair_gen(_generate_key_pair, curve)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True)


@pytest.mark.skip(reason="KeyGen arbitrarily fails TestU01")
@pytest.mark.parametrize(
    "curve",
    [
        ECDSA.Curve.P224,
        ECDSA.Curve.P256,
        ECDSA.Curve.P384,
        ECDSA.Curve.P521,
    ],
)
def test_key_pair_pycryptodome(curve: ECDSA.Curve):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_key_pair`.

    Uses :mod:`pycryptodome` to generate the keys. We only test the P-curves, as
    pycryptodome doesn't support the NIST binary curves.
    """

    def _generate_key_pair() -> tuple[int, int, int]:
        from Crypto.PublicKey import ECC

        key = ECC.generate(curve=str(curve))
        return (int(key.d), key.pointQ.x, key.pointQ.y)

    group = ECDSA.test_key_pair_gen(_generate_key_pair, curve)
    assert group.check(fail_if_empty=True)


# TODO: some tests are skipped due to a lack of SigGen test vectors.
@pytest.mark.parametrize(
    ("curve", "algo"),
    [
        # Test a standard combination.
        (ECDSA.Curve.P224, ECDSA.Hash.SHA224),
        # Test another standard combination.
        (ECDSA.Curve.P256, ECDSA.Hash.SHA256),
        # Test a B curve.
        (ECDSA.Curve.B283, ECDSA.Hash.SHA384),
        # Test secp256k1.
        pytest.param(
            ECDSA.Curve.SECP256K1,
            ECDSA.Hash.SHA512,
            marks=pytest.mark.skip(reason="No SigGen vectors for secp256k1"),
        ),
        # Test Brainpool.
        pytest.param(
            ECDSA.Curve.BRAINPOOLP384R1,
            ECDSA.Hash.SHA384,
            marks=pytest.mark.skip(reason="No SigGen vectors for Brainpool curves"),
        ),
        # Test SHA-3.
        pytest.param(
            ECDSA.Curve.P521,
            ECDSA.Hash.SHA3_512,
            marks=pytest.mark.skip(reason="No SigGen vectors for SHA-3"),
        ),
        # Test a truncated hash.
        (ECDSA.Curve.P384, ECDSA.Hash.SHA512_256),
    ],
)
def test_sign_verify_invariant(curve: ECDSA.Curve, algo: ECDSA.Hash):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_sign_verify_invariant`.

    Uses :mod:`cryptography`'s implementation to sign messages.
    """

    def sign_der(sk: bytes, msg: bytes) -> bytes:
        return ECDSA._sign(sk, algo, msg)

    def verify_der(pk: bytes, msg: bytes, sig: bytes):
        return ECDSA._verify(pk, algo, msg, sig)

    results = ECDSA.test_sign_verify_invariant(
        sign_der,
        verify_der,
        curve,
        algo,
        ECDSA.KeyEncoding.DER,
        ECDSA.PubKeyEncoding.DER,
    )
    console.print_results(results)
    assert results.check(fail_if_empty=True)


@pytest.mark.parametrize(
    ("curve", "algo"),
    [
        # Test standard combinations.
        (ECDSA.Curve.P224, ECDSA.Hash.SHA224),
        (ECDSA.Curve.P256, ECDSA.Hash.SHA256),
        (ECDSA.Curve.P384, ECDSA.Hash.SHA384),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512),
        # Test B curves.
        (ECDSA.Curve.B283, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B409, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B571, ECDSA.Hash.SHA512),
        # Test a truncated hash.
        (ECDSA.Curve.P384, ECDSA.Hash.SHA512_256),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512_224),
    ],
)
def test_output(curve: ECDSA.Curve, algo: ECDSA.Hash, tmp_path: Path):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_output_verify`.

    It uses existing test vectors to create two files: one filled with valid signatures
    and another with invalid ones. All tests must pass with the valid signatures, while
    all tests must fail with the invalid ones. The number of tests is verified.
    """
    output = generate_ecdsa_sigs(curve, algo, True)
    output_file = tmp_path / f"ecdsa_{str(curve)}_{str(algo).replace('/', '')}.txt"
    output_file.write_text(output)

    rd = ECDSA.test_output_sign(
        str(output_file), curve, algo, ECDSA.PubKeyEncoding.UNCOMPRESSED
    )
    console.print_results(rd)
    assert rd.check(fail_if_empty=True), "There are failed tests with valid values"


@pytest.mark.parametrize(
    ("curve", "algo"),
    [
        # Test standard combinations.
        (ECDSA.Curve.P224, ECDSA.Hash.SHA224),
        (ECDSA.Curve.P256, ECDSA.Hash.SHA256),
        (ECDSA.Curve.P384, ECDSA.Hash.SHA384),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512),
        # Test B curves.
        (ECDSA.Curve.B283, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B409, ECDSA.Hash.SHA256),
        (ECDSA.Curve.B571, ECDSA.Hash.SHA512),
        # Test a truncated hash.
        (ECDSA.Curve.P384, ECDSA.Hash.SHA512_256),
        (ECDSA.Curve.P521, ECDSA.Hash.SHA512_224),
    ],
)
def test_output_invalid(curve: ECDSA.Curve, algo: ECDSA.Hash, tmp_path: Path):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_output_verify`."""
    output = generate_ecdsa_sigs(curve, algo, False)
    output_file = (
        tmp_path / f"ecdsa_{str(curve)}_{str(algo).replace('/', '')}_invalid.txt"
    )
    output_file.write_text(output)

    rd = ECDSA.test_output_sign(
        str(output_file), curve, algo, ECDSA.PubKeyEncoding.UNCOMPRESSED
    )
    console.print_results(rd)
    assert not rd.check()
