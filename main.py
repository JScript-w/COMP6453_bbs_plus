import tests
import time


def main():
    print("1. basic\n2. selective_disclosure\n3. update\n4. bench")
    test_type = int(input("Input test type number: "))

    if test_type == 1:
        start = time.perf_counter()
        tests.test_basic.test_sign_verify()
        end = time.perf_counter()
        print(f"Time for basic test (bls12_v1): {end - start}")

        start = time.perf_counter()
        tests.test_basic_v2.test_sign_verify_v2()
        end = time.perf_counter()
        print(f"Time for basic test (bls12_v2): {end - start}")

        start = time.perf_counter()
        tests.test_basic_bn254.test_sign_verify_bn254()
        end = time.perf_counter()
        print(f"Time for basic test (bn254): {end - start}")

    elif test_type == 2:
        start = time.perf_counter()
        tests.test_selective_disclosure.test_proof()
        end = time.perf_counter()
        print(f"Time for selective disclosure test (bls12_v1): {end - start}")

        start = time.perf_counter()
        tests.test_selective_disclosure_v2.test_proof_v2()
        end = time.perf_counter()
        print(f"Time for selective disclosure test (bls12_v2): {end - start}")

        start = time.perf_counter()
        tests.test_selective_disclosure_bn254.test_proof_bn254()
        end = time.perf_counter()
        print(f"Time for selective disclosure test (bn254): {end - start}")

    elif test_type == 3:
        start = time.perf_counter()
        tests.test_update()
        end = time.perf_counter()
        print(f"Time for update test (bls12_v1): {end - start}")

        start = time.perf_counter()
        tests.test_update_v2()
        end = time.perf_counter()
        print(f"Time for update test (bls12_v2): {end - start}")

        start = time.perf_counter()
        tests.test_update_bn254()
        end = time.perf_counter()
        print(f"Time for update test (bn254): {end - start}")

    else:
        start = time.perf_counter()
        tests.bench()
        end = time.perf_counter()
        print(f"Time for benchmark (bls12_v1): {end - start}")

        start = time.perf_counter()
        tests.bench_v2()
        end = time.perf_counter()
        print(f"Time for benchmark (bls12_v2): {end - start}")


if __name__ == "__main__":
    main()
