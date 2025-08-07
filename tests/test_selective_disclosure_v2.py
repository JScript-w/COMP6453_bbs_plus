from src.bls12.v2 import KeyPair, sign, prove_disclosure, verify_disclosure


def test_proof_v2():
    kp = KeyPair.generate(5)
    msgs = ["x", "y", "z"]
    sig = sign(kp, msgs)
    proof = prove_disclosure(kp.get_pk(), sig, msgs, disclose_idx=[1])
    if verify_disclosure(kp.get_pk(), proof, total_attrs=len(msgs)):
        print("Success!")
    else:
        print("Failed!")
# Import necessary functions and classes from bls12 version 2

# Define a test function for selective disclosure proof in version 2
# Generate a key pair with parameter 5
# Define messages to sign
# Sign the messages using the key pair
# Create a proof that selectively discloses only the attribute at index 1
# Verify the selective disclosure proof with the public key and total number of attributes
# Print success message if verification passes, otherwise print failure message
