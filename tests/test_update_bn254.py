from src.bn254.v1 import KeyPair, sign, update_attributes, verify


def test_update_bn254():
    kp = KeyPair.generate()
    msgs = ["m1", "m2", "m3"]
    sig = sign(kp.sk, msgs)
    sig2 = update_attributes(kp.sk, sig, msgs, {2: "m3*"})
    msgs[2] = "m3*"
    assert verify(kp.pk, sig2, msgs)
# Import required functions and classes from bls12 version 1

# Define a test function for updating signed attributes
# Generate a new key pair
# Define original messages
# Sign the original messages using the secret key
# Update the signature with a modified attribute at index 2
# Update the message list to reflect the changed attribute
# Verify the updated signature with the public key and modified messages
