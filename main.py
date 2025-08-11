import tests
import time
import os

from tests.benchmark import bench


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def exec_test(func, test_name, curve_name):
    print("=" * 20 + f" {curve_name} " + "=" * 20)
    start = time.perf_counter()
    result = func()
    end = time.perf_counter()

    output = "Success" if result else "Failed!"
    print(f"1. Result: {output}")
    print(f"2. Time for {test_name}: {end - start}")


def main():
    while True:
        clear_screen()
        print("1. basic\n2. selective_disclosure\n3. update\n4. bench\n0. Exit")
        test_type = int(input("Input test type number: "))
        if test_type == 0:
            exit(1)

        clear_screen()
        print("1. BLS12_V1\n2. BLS12_V2\n3. ALL\n0. Back")
        if test_type == 1:
            test_type = int(input("Input test curve number: "))

            if test_type == 1:
                exec_test(tests.test_basic.test_sign_verify, "basic test", "BLS12_V1")

            elif test_type == 2:
                exec_test(
                    tests.test_basic_v2.test_sign_verify_v2, "basic test", "BLS12_V2"
                )

            elif test_type == 3:
                exec_test(tests.test_basic.test_sign_verify, "basic test", "BLS12_V1")
                exec_test(
                    tests.test_basic_v2.test_sign_verify_v2, "basic test", "BLS12_V2"
                )

            else:
                main()

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

            elif test_type == 3:
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

            else:
                main()

        elif test_type == 3:
            test_type = int(input("Input test curve number: "))

            if test_type == 1:
                exec_test(tests.test_update, "update test", "BLS_V1")

            elif test_type == 2:
                exec_test(tests.test_update_v2, "update test", "BLS_V2")

            elif test_type == 3:
                exec_test(tests.test_update, "update test", "BLS_V1")
                exec_test(tests.test_update_v2, "update test", "BLS_V2")

            else:
                main()

        elif test_type == 4:
            test_type = int(input("Input test curve number: "))

            if test_type == 1:
                tests.bench()

            elif test_type == 2:
                tests.bench_v2()

            elif test_type == 3:
                tests.bench()
                tests.bench_v2()

            else:
                main()

        input("Press any key to continue...")


if __name__ == "__main__":
    main()
