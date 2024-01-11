from random import randint


def zero_bytes(size: int) -> bytes:
    assert size >= 0
    return bytes([0 for _ in range(size)])


def random_bytes(size: int) -> bytes:
    assert size >= 0
    return bytes([randint(0, 255) for _ in range(size)])
