from random import randint


def zero_bytes(size: int) -> bytes:
    if size < 0:
        raise ValueError

    return bytes([0 for _ in range(size)])


def random_bytes(size: int) -> bytes:
    if size < 0:
        raise ValueError

    return bytes([randint(0, 255) for _ in range(size)])
