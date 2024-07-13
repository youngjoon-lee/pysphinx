from unittest import TestCase

from pysphinx.const import (
    DEFAULT_MAX_PLAIN_PAYLOAD_SIZE,
    DEFAULT_PAYLOAD_SIZE,
    PAYLOAD_TRAILING_PADDING_INDICATOR,
    SECURITY_PARAMETER,
)
from pysphinx.payload import Payload


class TestPayload(TestCase):
    def test_default_max_plain_payload_size(self):
        plain_payload = b"hello"
        payload = Payload.build(plain_payload, [], DEFAULT_MAX_PLAIN_PAYLOAD_SIZE)
        self.assertEqual(DEFAULT_PAYLOAD_SIZE, len(payload.data))
        self.assertEqual(plain_payload, payload.recover_plain_playload())

    def test_custom_max_plain_payload_size(self):
        max_plain_payload_size = 10
        expected_payload_size = (
            SECURITY_PARAMETER
            + max_plain_payload_size
            + len(PAYLOAD_TRAILING_PADDING_INDICATOR)
        )

        plain_payload = b"hello"
        payload = Payload.build(plain_payload, [], max_plain_payload_size)
        self.assertEqual(expected_payload_size, len(payload.data))
        self.assertEqual(plain_payload, payload.recover_plain_playload())

        plain_payload = b"bye"
        payload = Payload.build(plain_payload, [], max_plain_payload_size)
        self.assertEqual(expected_payload_size, len(payload.data))
        self.assertEqual(plain_payload, payload.recover_plain_playload())

        plain_payload = b"too long............................"
        with self.assertRaises(ValueError) as context:
            _ = Payload.build(plain_payload, [], max_plain_payload_size)
        self.assertIn("plain_payload is too long", str(context.exception))
