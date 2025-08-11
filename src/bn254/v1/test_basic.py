import secrets
from bn254.v1 import keygen, signer, verifier

def test_basic():
    # Generate random key pair
    sk, pk = keygen.keygen()
    # Generate a list of random attributes (e.g., 3 attributes for testing)
    attrs = [secrets.token_bytes(16) for _ in range(3)]
    # Sign the attributes
    sig = signer.sign(sk, attrs)
    # Verify the signature
    valid = verifier.verify(pk, sig, attrs)
    print("Signature valid:", valid)
    assert valid, "BBS+ signature verification failed"

if __name__ == "__main__":
    test_basic()
