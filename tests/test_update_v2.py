from bls12.v2 import KeyPair, sign, update_attributes, verify


def test_update_v2():
    kp = KeyPair.generate(5)
    msgs = ["m1", "m2", "m3"]
    sig = sign(kp, msgs)
    sig2 = update_attributes(kp, sig, msgs, {2: "m3*"})
    msgs[2] = "m3*"
    assert verify(kp.get_pk(), sig2, msgs)
