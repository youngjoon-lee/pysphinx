from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pysphinx.const import DEFAULT_MAX_ROUTE_LENGTH, DEFAULT_PAYLOAD_SIZE
from pysphinx.node import Node
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
        deserialized = SphinxPacket.from_bytes(serialized)
        self.assertEqual(packet, deserialized)

    def test_constant_packet_size_based_on_max_route_length(self):
        private_key = X25519PrivateKey.generate()
        node = Node(private_key.public_key(), random_bytes(32))

        msg = random_bytes(500)
        packet_1mix = SphinxPacket.build(msg, [node], node)
        packet_2mix = SphinxPacket.build(msg, [node, node], node)
        self.assertEqual(len(packet_1mix.bytes()), len(packet_2mix.bytes()))

        packet_1mix_long = SphinxPacket.build(
            msg, [node], node, DEFAULT_MAX_ROUTE_LENGTH * 2
        )
        packet_2mix_long = SphinxPacket.build(
            msg, [node, node], node, DEFAULT_MAX_ROUTE_LENGTH * 2
        )
        self.assertEqual(len(packet_1mix_long.bytes()), len(packet_2mix_long.bytes()))

        self.assertGreater(len(packet_1mix_long.bytes()), len(packet_1mix.bytes()))

    def test_custom_max_plain_payload_size(self):
        private_key = X25519PrivateKey.generate()
        node = Node(private_key.public_key(), random_bytes(32))

        max_plain_payload_size = 3000
        msg = random_bytes(2000)
        packet = SphinxPacket.build(
            msg, [node], node, max_plain_payload_size=max_plain_payload_size
        )

        processed_packet = packet.process(private_key)
        if not isinstance(processed_packet, ProcessedFinalHopPacket):
            self.fail()
        self.assertEqual(msg, processed_packet.payload.recover_plain_playload())

        longer_msg = random_bytes(max_plain_payload_size)
        packet_with_longer_msg = SphinxPacket.build(
            longer_msg, [node], node, max_plain_payload_size=max_plain_payload_size
        )
        self.assertEqual(len(packet.bytes()), len(packet_with_longer_msg.bytes()))

        processed_packet = packet_with_longer_msg.process(private_key)
        if not isinstance(processed_packet, ProcessedFinalHopPacket):
            self.fail()
        self.assertEqual(longer_msg, processed_packet.payload.recover_plain_playload())
