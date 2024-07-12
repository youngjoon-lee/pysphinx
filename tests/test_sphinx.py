from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pysphinx.node import Node
from pysphinx.payload import DEFAULT_PAYLOAD_SIZE
from pysphinx.sphinx import (
    ProcessedFinalHopPacket,
    ProcessedForwardHopPacket,
    SphinxPacket,
)
from pysphinx.utils import random_bytes


class TestSphinx(TestCase):
    def test_sphinx(self):
        private_keys = [X25519PrivateKey.generate() for _ in range(4)]
        nodes = [
            Node(private_key.public_key(), random_bytes(32))
            for private_key in private_keys
        ]
        destination = nodes[0]
        route = nodes[1:4]
        private_keys_for_route = private_keys[1:4]

        msg = random_bytes(500)
        packet = SphinxPacket.build(msg, route, destination)

        # Process packet with the first mix node in the route
        processed_packet = packet.process(private_keys_for_route[0])
        if not isinstance(processed_packet, ProcessedForwardHopPacket):
            self.fail()
        self.assertEqual(processed_packet.next_node_address, route[1].addr)
        self.assertEqual(len(packet.bytes()), len(processed_packet.next_packet.bytes()))

        # Process packet with the second mix node in the route
        processed_packet = processed_packet.next_packet.process(
            private_keys_for_route[1]
        )
        if not isinstance(processed_packet, ProcessedForwardHopPacket):
            self.fail()
        self.assertEqual(processed_packet.next_node_address, route[2].addr)
        self.assertEqual(len(packet.bytes()), len(processed_packet.next_packet.bytes()))

        # Process packet with the third mix node in the route
        processed_packet = processed_packet.next_packet.process(
            private_keys_for_route[2]
        )
        if not isinstance(processed_packet, ProcessedFinalHopPacket):
            self.fail()
        self.assertEqual(processed_packet.destination_node_address, destination.addr)
        self.assertEqual(DEFAULT_PAYLOAD_SIZE, len(processed_packet.payload.data))

        # Verify message as a destination
        self.assertEqual(processed_packet.payload.recover_plain_playload(), msg)

    def test_sphinx_serde(self):
        private_key = X25519PrivateKey.generate()
        node = Node(private_key.public_key(), random_bytes(32))

        packet = SphinxPacket.build(random_bytes(500), [node], node)

        serialized = packet.bytes()
        deserilized = SphinxPacket.from_bytes(serialized)
        self.assertEqual(packet, deserilized)

    def test_sphinx_custom_max_message_size(self):
        private_key = X25519PrivateKey.generate()
        node = Node(private_key.public_key(), random_bytes(32))

        msg = random_bytes(3000)
        packet = SphinxPacket.build(msg, [node], node, max_message_size=len(msg) + 1000)

        processed_packet = packet.process(private_key)
        if not isinstance(processed_packet, ProcessedFinalHopPacket):
            self.fail()
        self.assertEqual(msg, processed_packet.payload.recover_plain_playload())
