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
 # Uncomment this block to run the basic sign/verify test for version 1
    # start = time.perf_counter()
    # tests.test_basic.test_sign_verify()
    # end = time.perf_counter()
    # print(f"Time taken for basic v1 test: {end - start:.4f} seconds")

    # Uncomment this block to run the basic sign/verify test for version 2
    # start = time.perf_counter()
    # tests.test_basic_v2.test_sign_verify_v2()
    # end = time.perf_counter()
    # print(f"Time taken for basic v2 test: {end - start:.4f} seconds")

    # Uncomment this block to run the selective disclosure proof test for version 1
    # start = time.perf_counter()
    # tests.test_selective_disclosure.test_proof()
    # end = time.perf_counter()
    # print(f"Time taken for selective disclosure v1 test: {end - start:.4f} seconds")

    # Run the selective disclosure proof test for version 2
