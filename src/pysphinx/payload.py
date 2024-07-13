from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from pysphinx.const import PAYLOAD_TRAILING_PADDING_INDICATOR, SECURITY_PARAMETER
from pysphinx.crypto import lioness_decrypt, lioness_encrypt
from pysphinx.utils import zero_bytes


@dataclass
class Payload:
    data: bytes

    @classmethod
    def build(
        cls,
        plain_payload: bytes,
        payload_keys: list[bytes],
        max_plain_payload_size: int,
    ) -> Self:
        payload = cls.__add_padding(plain_payload, max_plain_payload_size)
        for payload_key in reversed(payload_keys):
            payload = lioness_encrypt(payload, payload_key)
        return cls(payload)

    @staticmethod
    def __add_padding(plain_payload: bytes, max_plain_payload_size: int) -> bytes:
        """
        Add leading and trailing padding to a plain payload

        This padding mechanism is the same as Nym's Sphinx implementation.
        """
        if len(plain_payload) > max_plain_payload_size:
            raise ValueError("plain_payload is too long", len(plain_payload))

        return (
            zero_bytes(SECURITY_PARAMETER)
            + plain_payload
            + PAYLOAD_TRAILING_PADDING_INDICATOR
            + zero_bytes(max_plain_payload_size - len(plain_payload))
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
