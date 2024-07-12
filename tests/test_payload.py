from typing import override
from unittest import TestCase

from pysphinx.config import Config
from pysphinx.const import (
    DEFAULT_PAYLOAD_SIZE,
    PAYLOAD_TRAILING_PADDING_INDICATOR,
    SECURITY_PARAMETER,
)
from pysphinx.payload import Payload


class TestPayload(TestCase):
    @override
    def setUp(self) -> None:
        Config.reset()

    def test_default_max_plain_payload_size(self):
        plain_payload = b"hello"
        payload = Payload.build(plain_payload, [])
        self.assertEqual(DEFAULT_PAYLOAD_SIZE, len(payload.data))
        self.assertEqual(plain_payload, payload.recover_plain_playload())

    def test_custom_max_plain_payload_size(self):
        Config.set_max_message_size(10)
        expected_payload_size = (
            SECURITY_PARAMETER
            + Config.max_message_size
            + len(PAYLOAD_TRAILING_PADDING_INDICATOR)
        )

        plain_payload = b"hello"
        payload = Payload.build(plain_payload, [])
        self.assertEqual(expected_payload_size, len(payload.data))
        self.assertEqual(plain_payload, payload.recover_plain_playload())

        plain_payload = b"bye"
        payload = Payload.build(plain_payload, [])
        self.assertEqual(expected_payload_size, len(payload.data))
        self.assertEqual(plain_payload, payload.recover_plain_playload())

        plain_payload = b"too long............................"
        with self.assertRaises(ValueError) as context:
            _ = Payload.build(plain_payload, [])
        self.assertIn("plain_payload is too long", str(context.exception))
