from bbsplus_bls12_v1 import KeyPair, sign, update_attributes, verify


def test_update():
    kp = KeyPair.generate()
    msgs = ["m1", "m2", "m3"]
    sig = sign(kp.sk, msgs)
    sig2 = update_attributes(kp.sk, sig, msgs, {2: "m3*"})
    msgs[2] = "m3*"
    assert verify(kp.pk, sig2, msgs)
