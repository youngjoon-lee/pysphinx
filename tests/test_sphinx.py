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
        nodes = [Node(X25519PrivateKey.generate(), random_bytes(32)) for _ in range(12)]
        destination = nodes[0]
        route = [nodes[i] for i in range(1, 4)]

        msg = random_bytes(500)
        packet = SphinxPacket.build(msg, route, destination)

        # Process packet with the first mix node in the route
        processed_packet = packet.process(route[0].private_key)
        if not isinstance(processed_packet, ProcessedForwardHopPacket):
            self.fail()
        self.assertEqual(processed_packet.next_node_address, route[1].addr)

        # Process packet with the second mix node in the route
        processed_packet = processed_packet.next_packet.process(route[1].private_key)
        if not isinstance(processed_packet, ProcessedForwardHopPacket):
            self.fail()
        self.assertEqual(processed_packet.next_node_address, route[2].addr)

        # Process packet with the third mix node in the route
        processed_packet = processed_packet.next_packet.process(route[2].private_key)
        if not isinstance(processed_packet, ProcessedFinalHopPacket):
            self.fail()
        self.assertEqual(processed_packet.destination_node_address, destination.addr)

        # Verify message as a destination
        self.assertEqual(processed_packet.payload.recover_plain_playload(), msg)
