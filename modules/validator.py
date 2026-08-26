import ipaddress


def is_valid_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    print(is_valid_ip("127.0.0.1"))
    print(is_valid_ip("999.999.999.999"))