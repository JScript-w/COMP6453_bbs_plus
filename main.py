import tests
import time


def main():
    print("1. basic\n2. selective_disclosure\n3. update\n4. bench")
    test_type = int(input("Input test type number: "))

    if test_type == 1:
        start = time.perf_counter()
        tests.test_basic.test_sign_verify()
        end = time.perf_counter()
        print(f"运行v1版本基础测试耗时：{end - start}")

        start = time.perf_counter()
        tests.test_basic_v2.test_sign_verify_v2()
        end = time.perf_counter()
        print(f"运行v2版本基础测试耗时：{end - start}")

    elif test_type == 2:
        start = time.perf_counter()
        tests.test_selective_disclosure.test_proof()
        end = time.perf_counter()
        print(f"运行v1版本选择性披露测试耗时：{end - start}")

        start = time.perf_counter()
        tests.test_selective_disclosure_v2.test_proof_v2()
        end = time.perf_counter()
        print(f"运行v2版本选择性披露测试耗时：{end - start}")

    elif test_type == 3:
        start = time.perf_counter()
        tests.test_update()
        end = time.perf_counter()
        print(f"运行v1版本更新测试耗时：{end - start}")

        start = time.perf_counter()
        tests.test_update_v2()
        end = time.perf_counter()
        print(f"运行v2版本更新测试耗时：{end - start}")

    else:
        start = time.perf_counter()
        tests.bench()
        end = time.perf_counter()
        print(f"运行v1版本压力测试耗时：{end - start}")

        start = time.perf_counter()
        tests.bench_v2()
        end = time.perf_counter()
        print(f"运行v2版本压力测试耗时：{end - start}")


if __name__ == "__main__":
    main()
