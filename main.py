import tests
import time
import os


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def exec_test(func, test_name, curve_name):
    start = time.perf_counter()
    result = func()
    end = time.perf_counter()

    output = "Success!" if result else "Failed!"
    print(output, end=" ")
    print(f"Time for {test_name} ({curve_name}): {end - start}")


def main():
    clear_screen()
    print("1. basic\n2. selective_disclosure\n3. update\n4. bench")
    test_type = int(input("Input test type number: "))

    clear_screen()
    print("1. BLS12_V1\n2. BLS12_V2\n3. ALL")
    if test_type == 1:
        test_type = int(input("Input test curve number: "))

        if test_type == 1:
            exec_test(tests.test_basic.test_sign_verify, "basic test", "BLS12_V1")

        elif test_type == 2:
            exec_test(tests.test_basic_v2.test_sign_verify_v2, "basic test", "BLS12_V2")

        else:
            exec_test(tests.test_basic.test_sign_verify, "basic test", "BLS12_V1")
            exec_test(tests.test_basic_v2.test_sign_verify_v2, "basic test", "BLS12_V2")

    elif test_type == 2:
        test_type = int(input("Input test curve number: "))

        if test_type == 1:
            exec_test(
                tests.test_selective_disclosure.test_proof,
                "selective_disclosure",
                "BLS_V1",
            )

        elif test_type == 2:
            exec_test(
                tests.test_selective_disclosure_v2.test_proof_v2,
                "selective_disclosure",
                "BLS_V2",
            )

        else:
            exec_test(
                tests.test_selective_disclosure.test_proof,
                "selective_disclosure",
                "BLS_V1",
            )
            exec_test(
                tests.test_selective_disclosure_v2.test_proof_v2,
                "selective_disclosure",
                "BLS_V2",
            )

    elif test_type == 3:
        test_type = int(input("Input test curve number: "))

        if test_type == 1:
            exec_test(tests.test_update, "update test", "BLS_V1")

        elif test_type == 2:
            exec_test(tests.test_update_v2, "update test", "BLS_V2")

        else:
            exec_test(tests.test_update, "update test", "BLS_V1")
            exec_test(tests.test_update_v2, "update test", "BLS_V2")

    else:
        test_type = int(input("Input test curve number: "))

        if test_type == 1:
            exec_test(tests.bench, "bench", "BLS_V1")

        elif test_type == 2:
            exec_test(tests.bench_v2, "bench", "BLS_V2")

        else:
            exec_test(tests.bench, "bench", "BLS_V1")
            exec_test(tests.bench_v2, "bench", "BLS_V2")


if __name__ == "__main__":
    main()
