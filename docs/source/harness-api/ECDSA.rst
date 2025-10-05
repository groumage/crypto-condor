ECDSA
=====

.. important::

   Only DER-encoded keys are supported for the C harness.

Test signing
------------

To test a function that signs with ECDSA, its name must conform to the following
convention:

.. code::

   CC_ECDSA_sign_<curve>_<hash function>_DER_[prehashed]

Where:

* ``curve`` is one of: ``P-224``, ``P-256``, ``P-384``, ``P-521``, ``B-283``, ``B-409``, ``B-571``.
* ``hash function`` is one of: ``SHA-256``, ``SHA-384``, ``SHA-512``.

.. c:function:: int ECDSA_sign(\
   uint8_t *sig, size_t sig_size,\
   const uint8_t *sk, size_t sk_size,\
   const uint8_t *msg, size_t msg_size)

   Signs a message with ECDSA.

   :param sig: **[Out]** An allocated buffer for returning the signature in DER format.
   :param sig_size: **[In]** The size of the ``sig`` buffer.
   :param sk: **[In]** The secret key to use for signing, in DER format.
   :param sk_len: **[In]** The size of the secret key in bytes.
   :param msg: **[In]** The message to sign.
   :param msg_size: **[In]** The size of the message in bytes.
   :returns: A status value.
   :retval 1: OK.
   :retval -1: An error occurred.

Verify
------

To test a function that verifies ECDSA signatures, its name must conform to the
following convention:

.. code::

   CC_ECDSA_verify_<curve>_<hash function>_[prehashed]

* ``curve`` is one of: ``P-224``, ``P-256``, ``P-384``, ``P-521``, ``B-283``, ``B-409``, ``B-571``.
* ``hash function`` is one of: ``SHA-256``, ``SHA-384``, ``SHA-512``.

Additionally, the following combinations of curve and hash function are available when
using resilience test vectors:

* ``P-224``, ``SHA3-256``.
* ``P-224``, ``SHA3-256``.
* ``P-256``, ``SHA3-256``.
* ``P-256``, ``SHA3-512``.
* ``P-384``, ``SHA3-384``.
* ``P-384``, ``SHA3-512``.
* ``P-521``, ``SHA3-512``.

.. c:function:: int ECDSA_verify(\
   const uint8_t *pk, const size_t pk_size,\
   const uint8_t *msg, const size_t msg_size,\
   const uint8_t *sig, const size_t sig_size)

   Verifies an ECDSA signature.

   :param pk: **[In]** The public key to use for verifying the signature.
   :param pk_size: **[In]** The size of ``pk`` in bytes.
   :param msg: **[In]** The message.
   :param msg_size: **[In]** The size of ``msg`` in bytes.
   :param sig: **[In]** The signature to verify.
   :param sig_size: **[In]** The size of ``sig`` in bytes.
   :returns: A status value.
   :retval 1: OK.
   :retval 0: The signature is invalid.
   :retval -1: An error occurred.
