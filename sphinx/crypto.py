from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes128ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES128(key), modes.CTR(nonce)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def compute_hmac_sha256(data: bytes, key: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def lioness_encrypt(data: bytes, key: bytes) -> bytes:
    # TODO: Couldn't find a lioness package that works with the latest Python. Implement it.
    return data


def lioness_decrypt(data: bytes, key: bytes) -> bytes:
    # TODO: Couldn't find a lioness package that works with the latest Python. Implement it.
    return data
