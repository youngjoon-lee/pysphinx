from dataclasses import dataclass
from typing import Self

from sphinx.const import SECURITY_PARAMETER
from sphinx.crypto import compute_hmac_sha256


@dataclass
class IntegrityHmac:
    """
    This class represents a HMAC-SHA256 that can be used for integrity authentication.
    """

    value: bytes

    def __init__(self, value: bytes):
        """Override the default constructor to assert the size of value"""
        assert len(value) == IntegrityHmac.size()
        self.value = value

    @staticmethod
    def size() -> int:
        return SECURITY_PARAMETER

    @classmethod
    def compute(cls, data: bytes, key: bytes) -> Self:
        """
        Build IntegrityHmac using data and key.
        """
        return cls(compute_hmac_sha256(data, key)[: cls.size()])

    def verify(self, data: bytes, key: bytes) -> bool:
        """
        Verify a HMAC computed from data and key matches with the expected HMAC.
        """
        return self.value == compute_hmac_sha256(data, key)[: self.size()]
