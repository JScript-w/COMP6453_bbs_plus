from src.bls12.v2 import KeyPair, sign, update_attributes, verify


def test_update_v2():
    kp = KeyPair.generate(5)
    msgs = ["m1", "m2", "m3"]
    sig = sign(kp, msgs)
    sig2 = update_attributes(kp, sig, msgs, {2: "m3*"})
    msgs[2] = "m3*"
    assert verify(kp.get_pk(), sig2, msgs)
# Import necessary functions and classes from bls12 version 2

# Define a test function for updating signed attributes in version 2
# Generate a key pair with parameter 5
# Define the original messages
# Sign the messages using the key pair
# Update the signature with a new value for the attribute at index 2
# Modify the message list to reflect the updated attribute
# Verify the updated signature using the public key and modified messages
