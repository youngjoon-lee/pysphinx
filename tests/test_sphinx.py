from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pysphinx.node import Node
from pysphinx.sphinx import (
    ProcessedFinalHopPacket,
    ProcessedForwardHopPacket,
    SphinxPacket,
)
from pysphinx.utils import random_bytes


class TestSphinx(TestCase):
    def test_sphinx(self):
        private_keys = [X25519PrivateKey.generate() for _ in range(12)]
        nodes = [
            Node(private_key.public_key(), random_bytes(32))
            for private_key in private_keys
        ]
        destination = nodes[0]
        route = [nodes[i] for i in range(1, 4)]
        private_keys_for_route = private_keys[1:4]

        msg = random_bytes(500)
        packet = SphinxPacket.build(msg, route, destination)

        # Process packet with the first mix node in the route
        processed_packet = packet.process(private_keys_for_route[0])
        if not isinstance(processed_packet, ProcessedForwardHopPacket):
            self.fail()
        self.assertEqual(processed_packet.next_node_address, route[1].addr)

        # Process packet with the second mix node in the route
        processed_packet = processed_packet.next_packet.process(
            private_keys_for_route[1]
        )
        if not isinstance(processed_packet, ProcessedForwardHopPacket):
            self.fail()
        self.assertEqual(processed_packet.next_node_address, route[2].addr)

        # Process packet with the third mix node in the route
        processed_packet = processed_packet.next_packet.process(
            private_keys_for_route[2]
        )
        if not isinstance(processed_packet, ProcessedFinalHopPacket):
            self.fail()
        self.assertEqual(processed_packet.destination_node_address, destination.addr)

        # Verify message as a destination
        self.assertEqual(processed_packet.payload.recover_plain_playload(), msg)

    def test_sphinx_serde(self):
        private_keys = [X25519PrivateKey.generate() for _ in range(12)]
        nodes = [
            Node(private_key.public_key(), random_bytes(32))
            for private_key in private_keys
        ]
        destination = nodes[0]
        route = [nodes[i] for i in range(1, 4)]

        packet = SphinxPacket.build(random_bytes(500), route, destination)

        serialized = packet.bytes()
        deserilized = SphinxPacket.from_bytes(serialized)
        self.assertEqual(packet, deserilized)
