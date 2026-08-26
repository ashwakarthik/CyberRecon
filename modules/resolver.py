import socket


def resolve_target(target):
    try:
        hostname = socket.gethostbyaddr(target)
        return hostname[0]
    except socket.herror:
        return None