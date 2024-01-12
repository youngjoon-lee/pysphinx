from random import randint


def zero_bytes(size: int) -> bytes:
    if size < 0:
        raise ValueError

    return bytes(size)


def random_bytes(size: int) -> bytes:
    if size < 0:
        raise ValueError

    return bytes(randint(0, 255) for _ in range(size))


def xor(ba1: bytes, ba2: bytes) -> bytes:
    """Bitwise XOR operation"""
    return bytes(_a ^ _b for _a, _b in zip(ba1, ba2))
