from bbsplus_bls12_v2 import KeyPair, sign, verify


def test_sign_verify():
    kp = KeyPair.generate(5)
    msgs = ["a", "b"]
    sig = sign(kp, msgs)
    assert verify(kp.get_pk(), sig, msgs)
