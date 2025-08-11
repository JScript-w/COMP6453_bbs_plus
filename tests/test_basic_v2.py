from src.bls12.v2 import KeyPair, sign, verify


def test_sign_verify_v2():
    kp = KeyPair.generate(5)
    msgs = ["a", "b"]
    sig = sign(kp, msgs)
    return verify(kp.get_pk(), sig, msgs)
