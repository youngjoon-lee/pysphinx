from dataclasses import dataclass
from typing import Self

from pysphinx.const import SECURITY_PARAMETER
from pysphinx.crypto import compute_hmac_sha256


@dataclass
class IntegrityHmac:
    """
    This class represents a HMAC-SHA256 that can be used for integrity authentication.
    """

    value: bytes

    SIZE: int = SECURITY_PARAMETER

    def __init__(self, value: bytes):
        """Override the default constructor to check the size of value"""
        if len(value) != self.SIZE:
            raise ValueError("invalid length of HMAC", len(value))

        self.value = value

    @classmethod
    def compute(cls, data: bytes, key: bytes) -> Self:
        """
        Build IntegrityHmac using data and key.
        """
        return cls(compute_hmac_sha256(data, key)[: cls.SIZE])

    def verify(self, data: bytes, key: bytes) -> bool:
        """
        Verify a HMAC computed from data and key matches with the expected HMAC.
        """
        return self.value == compute_hmac_sha256(data, key)[: self.SIZE]
