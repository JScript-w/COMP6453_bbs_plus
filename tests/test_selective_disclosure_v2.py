from bbsplus_bls12_v2 import KeyPair, sign, prove_disclosure, verify_disclosure


def test_proof():
    kp = KeyPair.generate(5)
    msgs = ["x", "y", "z"]
    sig = sign(kp, msgs)
    proof = prove_disclosure(kp.get_pk(), sig, msgs, disclose_idx=[1])
    assert verify_disclosure(kp.get_pk(), proof, total_attrs=len(msgs))
