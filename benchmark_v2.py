import timeit
from bls12.v2 import KeyPair, sign, verify


def bench(n_attrs: int, runs: int = 20):
    kp = KeyPair.generate(5)
    msgs = [f"m{i}" for i in range(n_attrs)]
    sign_t = timeit.timeit(lambda: sign(kp, msgs), number=runs) / runs
    sig = sign(kp, msgs)
    verify_t = timeit.timeit(lambda: verify(kp.get_pk(), sig, msgs), number=runs) / runs
    return sign_t * 1e3, verify_t * 1e3  # ms


if __name__ == "__main__":
    print(" n |  sign (ms) | verify (ms)")
    print("---+------------+------------")
    for n in (1, 5, 10, 20):
        s, v = bench(n)
        print(f"{n:2} | {s:10.3f} | {v:10.3f}")
# Import timeit module for measuring execution time
# Import KeyPair, sign, verify functions from bls12 version 2

# Define a benchmark function to measure signing and verification speed
# n_attrs: number of messages to sign
# runs: number of iterations for averaging (default 20)
# Generate a key pair with parameter 5
# Create a list of messages based on n_attrs
# Measure average signing time over runs
# Generate a signature for verification
# Measure average verification time over runs
# Return signing and verification times in milliseconds

# Main program starts here
# Print table header for results
# Loop over message counts: 1, 5, 10, and 20
# Run benchmark and print formatted timing results
