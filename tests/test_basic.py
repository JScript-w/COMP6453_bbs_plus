from bls12.v1 import KeyPair, sign, verify


def test_sign_verify():
    kp = KeyPair.generate()
    msgs = ["a", "b"]
    sig = sign(kp.sk, msgs)
    assert verify(kp.pk, sig, msgs)
