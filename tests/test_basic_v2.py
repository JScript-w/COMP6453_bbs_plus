from src.bls12.v2 import KeyPair, sign, verify


def test_sign_verify_v2():
    kp = KeyPair.generate(5)
    msgs = ["a", "b"]
    sig = sign(kp, msgs)
    assert verify(kp.get_pk(), sig, msgs)
# Import the functions and classes from version 2
# Define a test function for version 2 sign and verify
# Generate a key pair with 5 messages (public parameters)
# Define a list of messages to be signed
# Sign the messages using the key pair
# Verify the signature using the public key
