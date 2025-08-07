from bls12.v1 import KeyPair, sign, prove_disclosure, verify_disclosure


def test_proof():
    kp = KeyPair.generate()
    msgs = ["x", "y", "z"]
    sig = sign(kp.sk, msgs)
    proof = prove_disclosure(kp.pk, sig, msgs, disclose_idx=[1])
    assert verify_disclosure(kp.pk, proof, total_attrs=len(msgs))
# Import necessary functions and classes from bls12 version 1

# Define a test function for selective disclosure proof
# Generate a new key pair
# Define messages to sign
# Sign the messages using the secret key
# Generate a proof that selectively discloses only the attribute at index 1
# Verify the selective disclosure proof with the public key and total attributes
