import ipaddress
import socket


def get_target():
    while True:
        target = input("Enter target IP: ").strip()

        try:
            ipaddress.ip_address(target)
            return target

        except ValueError:
            print("[!] Invalid IP address.")
            print("[!] Example: 127.0.0.1")


def resolve_target(target):
    try:
        hostname = socket.gethostbyaddr(target)[0]
        return hostname

    except socket.herror:
        return "None"

    except socket.gaierror:
        return "None"

    except Exception:
        return "None"
