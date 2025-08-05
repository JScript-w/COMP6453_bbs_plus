import timeit
from bbsplus_pyecc import KeyPair, sign, verify


def bench(n_attrs: int, runs: int = 20):
    kp = KeyPair.generate()
    msgs = [f"m{i}" for i in range(n_attrs)]
    sign_t = timeit.timeit(lambda: sign(kp.sk, msgs), number=runs) / runs
    sig = sign(kp.sk, msgs)
    verify_t = timeit.timeit(lambda: verify(kp.pk, sig, msgs), number=runs) / runs
    return sign_t * 1e3, verify_t * 1e3  # ms


if __name__ == "__main__":
    print(" n |  sign (ms) | verify (ms)")
    print("---+------------+------------")
    for n in (1, 5, 10, 20):
        s, v = bench(n)
        print(f"{n:2} | {s:10.3f} | {v:10.3f}")
