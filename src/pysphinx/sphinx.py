from __future__ import annotations

from dataclasses import dataclass
from typing import List, Self

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from pysphinx.error import UnknownHeaderTypeError
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
        route: List[Node],
        destination: Node,
    ) -> Self:
        """
        This method is a constructor for packet senders.

        A packet sender has to determine a mix route and a mix destination.

        A message must fit into the capacity of a single Sphinx packet.
        For details, please see Payload.
        """
        header_and_payload_keys = SphinxHeader.build(
            X25519PrivateKey.generate(), route, destination
        )
        header = header_and_payload_keys[0]
        payload_keys = header_and_payload_keys[1]

        payload = Payload.build(message, payload_keys)

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
            case _:
                raise UnknownHeaderTypeError

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
    def from_bytes(cls, data: bytes) -> Self:
        a = 0
        b = 8
        header_size = int.from_bytes(data[a:b], byteorder="little")
        a = b
        b += header_size
        header = SphinxHeader.from_bytes(data[a:b])
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
