import tests
import time


def main():
    """
    start = time.perf_counter()
    tests.test_basic.test_sign_verify()
    end = time.perf_counter()
    print(f"运行v1版本基础测试耗时：{end - start}")

    start = time.perf_counter()
    tests.test_basic_v2.test_sign_verify_v2()
    end = time.perf_counter()
    print(f"运行v2版本基础测试耗时：{end - start}")

    # start = time.perf_counter()
    # tests.test_selective_disclosure.test_proof()
    # end = time.perf_counter()
    # print(f"运行v1版本选择性披露测试耗时：{end - start}")
    """

    start = time.perf_counter()
    tests.test_selective_disclosure_v2.test_proof_v2()
    end = time.perf_counter()
    print(f"运行v2版本选择性披露测试耗时：{end - start}")


if __name__ == "__main__":
    main()
