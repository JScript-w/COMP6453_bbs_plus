from bbsplus_pyecc import KeyPair, sign, prove_disclosure, verify_disclosure

def test_proof():
    kp = KeyPair.generate()
    msgs = ["x", "y", "z"]
    sig = sign(kp.sk, msgs)
    proof = prove_disclosure(kp.pk, sig, msgs, disclose_idx=[1])
    assert verify_disclosure(kp.pk, proof, total_attrs=len(msgs))
