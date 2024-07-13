from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from pysphinx.const import DEFAULT_MAX_PLAIN_PAYLOAD_SIZE, DEFAULT_MAX_ROUTE_LENGTH
from pysphinx.header.header import (
    ProcessedFinalHopHeader,
    ProcessedForwardHopHeader,
    SphinxHeader,
)
from pysphinx.node import Node, NodeAddress
from pysphinx.payload import Payload


@dataclass
class SphinxPacket:
    """
    A Sphinx packet that will be sent directly through network sockets
    """

    header: SphinxHeader
    payload: Payload

    @classmethod
    def build(
        cls,
        message: bytes,
        route: list[Node],
        destination: Node,
        max_route_length: int = DEFAULT_MAX_ROUTE_LENGTH,
        max_plain_payload_size: int = DEFAULT_MAX_PLAIN_PAYLOAD_SIZE,
    ) -> Self:
        """
        Constructs a Sphinx packet.

        Args:
            message: The message to be sent
            route: The route through which the message will be sent
            destination: The final destination node of the message
            max_route_length:
                The maximum length of mix route that the user can specify when creating a Sphinx packet.
                Even if the user specifies less shorter route,
                padding is added to ensure that all Sphinx packets have the uniform size.
                This padding is not distinguishable by mix nodes.
                In other words, mix nodes cannot know how many mix nodes the user specified in the route.
                If the user specifies a longer route than this value, an error is raised.
            max_plain_payload_size:
                The maximum size of payload that can be wrapped in a Sphinx packet
                Shorter payloads will be padded to this size to ensure that all Sphinx packets have the uniform size.
                Payloads longer than this size will raise an error.

        Raises:
            ValueError: If the message exceeds max_plain_payload_size

        Returns:
            Self: A Sphinx packet

        Notes:
            - If the message is shorter than max_plain_payload_size, zero padding is added to ensure uniform packet size.
        """
        header_and_payload_keys = SphinxHeader.build(
            X25519PrivateKey.generate(), route, max_route_length, destination
        )
        header = header_and_payload_keys[0]
        payload_keys = header_and_payload_keys[1]

        payload = Payload.build(message, payload_keys, max_plain_payload_size)

        return cls(header, payload)

    def process(
        self, private_key: X25519PrivateKey
    ) -> ProcessedForwardHopPacket | ProcessedFinalHopPacket:
        """
        Unwrap one layer of encapsulated routing information in the Sphinx packet using private_key.

        If there are other encapsulated layers left after being unwrapped, this method returns ProcessedForwardHopPacket.
        If not, this returns ProcessedFinalHopPacket.
        """
        processed_header = self.header.process(private_key)
        match processed_header:
            case ProcessedForwardHopHeader():
                return ProcessedForwardHopPacket(
                    SphinxPacket(
                        processed_header.next_header,
                        self.payload.unwrap(processed_header.payload_key),
                    ),
                    processed_header.next_node_address,
                )
            case ProcessedFinalHopHeader():
                return ProcessedFinalHopPacket(
                    processed_header.destination_address,
                    self.payload.unwrap(processed_header.payload_key),
                )

    def bytes(self):
        header = self.header.bytes()
        payload = self.payload.data
        return (
            len(header).to_bytes(8, byteorder="little")
            + header
            + len(payload).to_bytes(8, byteorder="little")
            + payload
        )

    @classmethod
    def from_bytes(
        cls, data: bytes, max_route_len: int = DEFAULT_MAX_ROUTE_LENGTH
    ) -> Self:
        a = 0
        b = 8
        header_size = int.from_bytes(data[a:b], byteorder="little")
        a = b
        b += header_size
        header = SphinxHeader.from_bytes(data[a:b], max_route_len)
        a = b
        b += 8
        payload_size = int.from_bytes(data[a:b], byteorder="little")
        a = b
        b += payload_size
        payload = Payload(data[a:b])
        return cls(header, payload)


@dataclass
class ProcessedForwardHopPacket:
    next_packet: SphinxPacket
    next_node_address: NodeAddress


@dataclass
class ProcessedFinalHopPacket:
    destination_node_address: NodeAddress
    payload: Payload
