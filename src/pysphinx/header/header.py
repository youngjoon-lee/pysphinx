from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from pysphinx.header.keys import KeyMaterial, RoutingKeys
from pysphinx.header.routing import EncapsulatedRoutingInformation, Filler
from pysphinx.node import Node, NodeAddress


@dataclass
class SphinxHeader:
    """
    A Sphinx header contains an encapsulated routing information
    and a shared secret that can be used to unwrap one layer of the encapsulated routing information.
    """

    shared_pubkey: X25519PublicKey
    routing_info: EncapsulatedRoutingInformation

    @classmethod
    def build(
        cls,
        initial_ephemeral_privkey: X25519PrivateKey,
        route: list[Node],
        max_route_length: int,
        destination: Node,
    ) -> tuple[Self, list[bytes]]:
        """
        Construct a SphinxHeader by encapsulating all routing information
        and keys that can be used to encrypt a payload.
        """
        key_material = KeyMaterial.derive(initial_ephemeral_privkey, route)
        filler = Filler.build(key_material.routing_keys, max_route_length)
        routing_info = EncapsulatedRoutingInformation.build(
            route, destination, key_material.routing_keys, filler
        )
        payload_keys = [
            routing_key.payload_key for routing_key in key_material.routing_keys
        ]
        return (cls(key_material.initial_ephemeral_pubkey, routing_info), payload_keys)

    def process(
        self, private_key: X25519PrivateKey
    ) -> ProcessedForwardHopHeader | ProcessedFinalHopHeader:
        """
        Unwrap one layer of encapsulated routing information using private_key.

        If there are other encapsulated layers left after being unwrapped, this method returns ProcessedForwardHopHeader.
        If not, this returns ProcessedFinalHopHeader.
        """
        routing_keys = self.compute_routing_keys(self.shared_pubkey, private_key)

        if not self.routing_info.integrity_mac.verify(
            self.routing_info.encrypted_routing_info.value,
            routing_keys.header_integrity_hmac_key,
        ):
            raise ValueError("HMAC authentication failed")

        routing_info_and_addr = self.routing_info.encrypted_routing_info.unwrap(
            routing_keys.stream_cipher_key
        )
        encapsulated_routing_info = routing_info_and_addr[0]
        next_node_address = routing_info_and_addr[1]

        if encapsulated_routing_info is not None:
            new_shared_pubkey = KeyMaterial.blind_shared_pubkey(
                self.shared_pubkey, routing_keys.blinding_factor
            )
            return ProcessedForwardHopHeader(
                SphinxHeader(new_shared_pubkey, encapsulated_routing_info),
                next_node_address,
                routing_keys.payload_key,
            )
        else:
            return ProcessedFinalHopHeader(next_node_address, routing_keys.payload_key)

    @staticmethod
    def compute_routing_keys(
        shared_pubkey: X25519PublicKey, private_key: X25519PrivateKey
    ) -> RoutingKeys:
        """
        Derive RoutingKeys from a shared key created by Diffie-Hellman key exchange between shared_pubkey and private_key.
        """
        dh_shared_key = private_key.exchange(shared_pubkey)
        return RoutingKeys.derive(dh_shared_key)

    def bytes(self) -> bytes:
        pubkey = self.shared_pubkey.public_bytes_raw()
        routing_info = self.routing_info.bytes()
        return (
            len(pubkey).to_bytes(8, byteorder="little")
            + pubkey
            + len(routing_info).to_bytes(8, byteorder="little")
            + routing_info
        )

    @classmethod
    def from_bytes(cls, data: bytes, max_route_len: int) -> Self:
        a = 0
        b = 8
        pubkey_size = int.from_bytes(data[a:b], byteorder="little")
        a = b
        b += pubkey_size
        pubkey = X25519PublicKey.from_public_bytes(data[a:b])
        a = b
        b += 8
        routing_info_size = int.from_bytes(data[a:b], byteorder="little")
        a = b
        b += routing_info_size
        routing_info = EncapsulatedRoutingInformation.from_bytes(
            data[a:b], max_route_len
        )
        return cls(pubkey, routing_info)


@dataclass
class ProcessedForwardHopHeader:
    """
    A forward-hop header unwrapped from SphinxHeader

    This class contains another SphinxHeader to be forwarded to the next mix node,
    and a payload key for the current mix node to decrypt one layer of payload encryption.
    """

    next_header: SphinxHeader
    next_node_address: NodeAddress
    payload_key: bytes


@dataclass
class ProcessedFinalHopHeader:
    """
    A final-hop header unwrapped from SphinxHeader

    This class contains a payload key for the current mix node to decrypt the last layer of payload encryption,
    and a destination address to which the decrypted payload will be delivered.
    """

    destination_address: NodeAddress
    payload_key: bytes
