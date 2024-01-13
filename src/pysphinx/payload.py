from __future__ import annotations

from dataclasses import dataclass
from typing import List, Self

from pysphinx.const import SECURITY_PARAMETER
from pysphinx.crypto import lioness_decrypt, lioness_encrypt
from pysphinx.utils import zero_bytes

# For the packet indistinguishability, the size of payload (padded) is a constant.
DEFAULT_PAYLOAD_SIZE = 1024
PAYLOAD_TRAILING_PADDING_INDICATOR = b"\x01"


@dataclass
class Payload:
    data: bytes

    @classmethod
    def build(cls, plain_payload: bytes, payload_keys: List[bytes]) -> Self:
        payload = cls.add_padding(plain_payload)
        for payload_key in reversed(payload_keys):
            payload = lioness_encrypt(payload, payload_key)
        return cls(payload)

    @staticmethod
    def add_padding(plain_payload: bytes) -> bytes:
        """
        Add leading and trailing padding to a plain payload

        This padding mechanism is the same as Nym's Sphinx implementation.
        """
        if len(plain_payload) > Payload.max_plain_payload_size():
            raise ValueError("Invalid length of plain_payload", len(plain_payload))

        padded = (
            zero_bytes(SECURITY_PARAMETER)
            + plain_payload
            + PAYLOAD_TRAILING_PADDING_INDICATOR
            + zero_bytes(
                DEFAULT_PAYLOAD_SIZE
                - SECURITY_PARAMETER
                - len(plain_payload)
                - len(PAYLOAD_TRAILING_PADDING_INDICATOR)
            )
        )
        assert len(padded) == DEFAULT_PAYLOAD_SIZE
        return padded

    @staticmethod
    def max_plain_payload_size() -> int:
        return (
            DEFAULT_PAYLOAD_SIZE
            - SECURITY_PARAMETER
            - len(PAYLOAD_TRAILING_PADDING_INDICATOR)
        )

    def unwrap(self, payload_key: bytes) -> Payload:
        """Unwrap a single layer of encryption"""
        return Payload(lioness_decrypt(self.data, payload_key))

    def recover_plain_playload(self) -> bytes:
        """
        After Payload has been unwrapped required number of times,
        this method must be called to parse the unwrapped payload into
        the original payload by removing leading/trailing paddings.
        """
        if not self.data.startswith(zero_bytes(SECURITY_PARAMETER)):
            raise ValueError("failed to find leading zero padding")

        indicator_idx = self.data.rfind(PAYLOAD_TRAILING_PADDING_INDICATOR)
        if indicator_idx == -1:
            raise ValueError("failed to find trailing padding indicator")

        return self.data[SECURITY_PARAMETER:indicator_idx]
