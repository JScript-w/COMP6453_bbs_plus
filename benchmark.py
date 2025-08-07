import timeit
from src.bls12.v1 import KeyPair, sign, verify


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
# Import the timeit module for performance measurement
# Import KeyPair, sign, verify functions from bls12 version 1

# Define a benchmarking function that measures signing and verifying times
# n_attrs: number of messages to sign
# runs: how many times to repeat for averaging (default 20)
# Generate a new key pair
# Create a list of messages based on n_attrs
# Measure average time to sign messages over runs
# Generate a signature for verification
# Measure average time to verify the signature over runs
# Return signing and verifying times in milliseconds

# If this script is run as main
# Print table header
# Loop over different message counts (1, 5, 10, 20)
# Run benchmark and print formatted results
