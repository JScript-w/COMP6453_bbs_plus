from tests import test_basic, test_basic_v2


def main():
    test_basic.test_sign_verify()
    test_basic_v2.test_sign_verify()


if __name__ == "__main__":
    main()
