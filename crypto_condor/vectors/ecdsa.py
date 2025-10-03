"""Enums for ECDSA."""

import strenum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class Curve(strenum.StrEnum):
    """The supported elliptic curves."""

    P224 = "P-224"
    P256 = "P-256"
    P384 = "P-384"
    P521 = "P-521"
    B283 = "B-283"
    B409 = "B-409"
    B571 = "B-571"
    SECP256K1 = "secp256k1"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    BRAINPOOLP384R1 = "brainpoolP384r1"
    BRAINPOOLP512R1 = "brainpoolP512r1"

    def __init__(self, value):
        """Override __init__ to add custom properties."""
        self._value_ = value
        match value:
            case "P-224" | "P-256" | "P-384" | "P-521":
                self._key_size_ = int(value[2:])
            case "secp256k1":
                self._key_size_ = 256
            case "brainpoolP256r1" | "brainpoolP384r1" | "brainpoolP512r1":
                self._key_size_ = int(value[10:13])
            case "B-283" | "B-409" | "B-571":
                self._key_size_ = int(value[2:])
            case _:
                raise ValueError(f"Unexpected enum value {value}")

    @property
    def key_size(self) -> int:
        """Returns the size of the keys in bits."""
        return self._key_size_

    @classmethod
    def from_name(cls, name: str):
        """Matches a curve name to its corresponding enum.

        Args:
            name: The name of the curve.

        Returns:
            The corresponding :class:`Curve`.

        Raises:
            ValueError: If the curve is not supported or the name not recognized.
        """
        match name.casefold():
            case (
                "p224"
                | "nist p-224"
                | "p-224"
                | "prime224v1"
                | "secp224r1"
                | "nistp224"
            ):
                return cls.P224
            case (
                "p256"
                | "nist p-256"
                | "p-256"
                | "prime256v1"
                | "secp256r1"
                | "nistp256"
            ):
                return cls.P256
            case (
                "p384"
                | "nist p-384"
                | "p-384"
                | "prime384v1"
                | "secp384r1"
                | "nistp384"
            ):
                return cls.P384
            case (
                "p521"
                | "nist p-521"
                | "p-521"
                | "prime521v1"
                | "secp521r1"
                | "nistp521"
            ):
                return cls.P521
            case "b283" | "b-283" | "sect283r1":
                return cls.B283
            case "b409" | "b-409" | "sect409r1":
                return cls.B409
            case "b571" | "b-571" | "sect571r1":
                return cls.B571
            case "secp256k1":
                return cls.SECP256K1
            case "brainpoolp256r1":
                return cls.BRAINPOOLP256R1
            case "brainpoolp384r1":
                return cls.BRAINPOOLP384R1
            case "brainpoolp512r1":
                return cls.BRAINPOOLP512R1
            case _:
                raise ValueError(f"Unsupported curve {name}")

    def get_curve_instance(self):
        """Returns an instance of the corresponding curve.

        Curves come from the :mod:`cryptography.hazmat.primitives.asymmetric.ec` module.
        """
        match self:
            case Curve.P224:
                return ec.SECP224R1()
            case Curve.P256:
                return ec.SECP256R1()
            case Curve.P384:
                return ec.SECP384R1()
            case Curve.P521:
                return ec.SECP521R1()
            case Curve.B283:
                return ec.SECT283R1()
            case Curve.B409:
                return ec.SECT409R1()
            case Curve.B571:
                return ec.SECT571R1()
            case Curve.SECP256K1:
                return ec.SECP256K1()
            case Curve.BRAINPOOLP256R1:
                return ec.BrainpoolP256R1()
            case Curve.BRAINPOOLP384R1:
                return ec.BrainpoolP384R1()
            case Curve.BRAINPOOLP512R1:
                return ec.BrainpoolP512R1()
            case _:
                raise ValueError(f"Unexpected curve: {str(self)}")


class Hash(strenum.StrEnum):
    """The supported hash functions."""

    SHA224 = "SHA-224"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    SHA512_224 = "SHA-512/224"
    SHA512_256 = "SHA-512/256"
    SHA3_224 = "SHA3-224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"

    @classmethod
    def from_name(cls, name: str):
        """Matches a hash function name to its corresponding enum.

        Args:
            name: The name of the hash function.

        Returns:
            The corresponding :class:`Hash`.

        Raises:
            ValueError: If the hash function is not supported or the name not
                recognized.
        """
        # Trying to be clever by case folding and removing symbols.
        match name.casefold().replace("-", "").replace("/", ""):
            case "sha224":
                return cls.SHA224
            case "sha256":
                return cls.SHA256
            case "sha384":
                return cls.SHA384
            case "sha512":
                return cls.SHA512
            case "sha512224":
                return cls.SHA512_224
            case "sha512256":
                return cls.SHA512_256
            case "sha3224":
                return cls.SHA3_224
            case "sha3256":
                return cls.SHA3_256
            case "sha3384":
                return cls.SHA3_384
            case "sha3512":
                return cls.SHA3_512
            case _:
                raise ValueError(f"Unsupported hash function {name}")

    def get_hash_instance(self):
        """Returns an instance of the corresponding hash function.

        Hash functions come from :mod:`cryptography.hazmat.primitives.hashes` module.
        """
        match self:
            case Hash.SHA224:
                return hashes.SHA224()
            case Hash.SHA256:
                return hashes.SHA256()
            case Hash.SHA384:
                return hashes.SHA384()
            case Hash.SHA512:
                return hashes.SHA512()
            case Hash.SHA512_224:
                return hashes.SHA512_224()
            case Hash.SHA512_256:
                return hashes.SHA512_256()
            case Hash.SHA3_224:
                return hashes.SHA3_224()
            case Hash.SHA3_256:
                return hashes.SHA3_256()
            case Hash.SHA3_384:
                return hashes.SHA3_384()
            case Hash.SHA3_512:
                return hashes.SHA3_512()
            case _:
                raise ValueError(f"Unexpected hash: {str(self)}")
