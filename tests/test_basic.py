from src.bls12.v1 import KeyPair, sign, verify


# This function tests the basic signing and verification process using BBS+.
# First, it generates a new key pair (public and secret key),
# then signs a list of messages using the secret key,
# and finally verifies the signature using the public key and original messages.
def test_sign_verify():
    kp = KeyPair.generate()
    msgs = ["a", "b"]
    sig = sign(kp.sk, msgs)
    return verify(kp.pk, sig, msgs)
