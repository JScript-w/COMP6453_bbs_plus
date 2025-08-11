import time
import secrets
import argparse
from bn254.v1 import keygen, signer, verifier

def benchmark(num_attrs: int, num_iters: int):
    # Generate a key pair
    sk, pk = keygen.keygen()
    # Generate random attributes
    attrs = [secrets.token_bytes(32) for _ in range(num_attrs)]
    # Pre-generate a signature to use for verify timing (to avoid including sign time in verify loop)
    signature = signer.sign(sk, attrs)

    # Measure signing time over num_iters iterations
    start = time.time()
    for _ in range(num_iters):
        _ = signer.sign(sk, attrs)
    end = time.time()
    avg_sign_time = (end - start) / num_iters

    # Measure verification time over num_iters iterations
    start = time.time()
    for _ in range(num_iters):
        _ = verifier.verify(pk, signature, attrs)
    end = time.time()
    avg_verify_time = (end - start) / num_iters

    print(f"Attributes: {num_attrs}, Iterations: {num_iters}")
    print(f"Average signing time: {avg_sign_time:.6f} seconds")
    print(f"Average verification time: {avg_verify_time:.6f} seconds")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BBS+ signature benchmark on BN254")
    parser.add_argument("-N", "--num_attrs", type=int, default=5, help="Number of attributes to sign")
    parser.add_argument("-T", "--num_iters", type=int, default=100, help="Number of iterations for benchmark")
    args = parser.parse_args()
    benchmark(args.num_attrs, args.num_iters)
