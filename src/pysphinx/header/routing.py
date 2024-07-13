from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Self

from pysphinx.const import (
    DELAY,
    DELAY_LENGTH,
    FLAG_LENGTH,
    NODE_ADDRESS_LENGTH,
    SURB_IDENTIFIER,
    SURB_IDENTIFIER_LENGTH,
    VERSION,
    VERSION_LENGTH,
)
from pysphinx.crypto import aes128ctr
from pysphinx.header.keys import RoutingKeys
from pysphinx.header.mac import IntegrityHmac
from pysphinx.node import Node, NodeAddress
from pysphinx.utils import random_bytes, xor, zero_bytes


@dataclass
class EncapsulatedRoutingInformation:
    """
    An encapsulated routing information that can be unwrapped by a certain mix node in the route.
    """

    # An encrypted routing information that can be decrypted by a certain mix node in the route.
    encrypted_routing_info: EncryptedRoutingInformation
    # For integrity authentication
    integrity_mac: IntegrityHmac

    @classmethod
    def build(
        cls,
        route: list[Node],
        destination: Node,
        routing_keys: list[RoutingKeys],
        filler: Filler,
    ) -> Self:
        """
        Build EncapsulatedRoutingInformation by building sub-EncapsulatedRoutingInformation recursively.
        """
        if len(route) == 0:
            raise ValueError("empty route")
        if len(route) != len(routing_keys):
            raise ValueError(
                "the length of routing_keys must be equal to the length of route"
            )

        final_keys = routing_keys[-1]
        encapsulated_destination_routing_info = cls.for_final_hop(
            destination, final_keys, filler, len(route)
        )

        return cls.for_forward_hops(
            encapsulated_destination_routing_info,
            route,
            routing_keys,
            filler.max_route_len,
        )

    @classmethod
    def for_final_hop(
        cls,
        destination: Node,
        routing_keys: RoutingKeys,
        filler: Filler,
        route_len: int,
    ) -> Self:
        """
        Build EncapsulatedRoutingInformation for the final mix node in the route that will forward payload to the destination.

        filler is used for the undistinguishability between forward-hop headers and a final-hop header.
        For more details, please see Filler.
        """
        encrypted_routing_info = (
            FinalRoutingInformation.build(destination.addr)
            .add_padding(route_len, filler.max_route_len)
            .encrypt(routing_keys.stream_cipher_key)
            .combine_with_filler(filler)
        )
        integrity_mac = IntegrityHmac.compute(
            encrypted_routing_info.value, routing_keys.header_integrity_hmac_key
        )
        return cls(encrypted_routing_info, integrity_mac)

    @classmethod
    def for_forward_hops(
        cls,
        encapsulated_destination_routing_info: Self,
        route: list[Node],
        routing_keys: list[RoutingKeys],
        max_route_len: int,
    ) -> Self:
        """
        Build EncapsulatedRoutingInformation for all mix nodes except the final mix node in the route.
        """
        next_encapsulated_routing_info = encapsulated_destination_routing_info

        # skip the first mixnodes because the sender will forward the packet to the first mixnode directly
        for i in reversed(range(1, len(route))):
            node = route[i]
            routing_key = routing_keys[i - 1]

            routing_info = RoutingInformation.build(
                node.addr, next_encapsulated_routing_info
            )
            encrypted_routing_info = routing_info.encrypt(
                routing_key.stream_cipher_key, max_route_len
            )
            integrity_mac = IntegrityHmac.compute(
                encrypted_routing_info.value, routing_key.header_integrity_hmac_key
            )
            next_encapsulated_routing_info = cls(encrypted_routing_info, integrity_mac)

        return next_encapsulated_routing_info

    def bytes(self) -> bytes:
        return self.integrity_mac.value + self.encrypted_routing_info.value

    @classmethod
    def from_bytes(cls, data: bytes, max_route_len: int) -> Self:
        return cls(
            EncryptedRoutingInformation(data[IntegrityHmac.SIZE :], max_route_len),
            IntegrityHmac(data[: IntegrityHmac.SIZE]),
        )


class RoutingFlag(Enum):
    ROUTING_FLAG_FORWARD_HOP = b"\x01"
    ROUTING_FLAG_FINAL_HOP = b"\x02"

    def bytes(self) -> bytes:
        return bytes(self.value)


@dataclass
class RoutingInformation:
    """
    Represent a forward-hop routing information not encrypted and not encapsulated
    """

    flag: RoutingFlag
    node_address: NodeAddress
    header_integrity_mac: bytes
    next_routing_info: TruncatedRoutingInformation

    # 60 bytes in total
    META_SIZE: int = (
        FLAG_LENGTH
        + VERSION_LENGTH
        + NODE_ADDRESS_LENGTH
        + DELAY_LENGTH
        + IntegrityHmac.SIZE
    )

    @classmethod
    def build(
        cls,
        node: NodeAddress,
        next_encapsulated_routing_info: EncapsulatedRoutingInformation,
    ) -> Self:
        return cls(
            RoutingFlag.ROUTING_FLAG_FORWARD_HOP,
            node,
            next_encapsulated_routing_info.integrity_mac.value,
            next_encapsulated_routing_info.encrypted_routing_info.truncate(),
        )

    def encrypt(self, key: bytes, max_route_len: int) -> EncryptedRoutingInformation:
        body = (
            self.flag.bytes()
            + VERSION
            + self.node_address
            + DELAY
            + self.header_integrity_mac
            + self.next_routing_info.value
        )
        return EncryptedRoutingInformation(
            encrypt(body, key, max_route_len), max_route_len
        )


@dataclass
class Filler:
    """
    This class represents a set of multiple fillers, 1 less than the length of mix route.
    A single filler has the same size as a single RoutingInformation.

    A single filler is used to make the routing information that has been unwrapped once
    have the same size as the routing information before unwrapped.

    For the same purpose, a set of multiple fillers (this class) is meant to be
    appended to a EncryptedPaddedFinalRoutingInformation.
    """

    value: bytes
    max_route_len: int

    """A size of a single filler, which is the same as the size of RoutingInformation"""
    ONE_STEP_SIZE: int = RoutingInformation.META_SIZE

    def __init__(self, value: bytes, max_route_len: int):
        """Override the default constructor to check the size of value."""
        if len(value) % self.ONE_STEP_SIZE != 0:
            raise ValueError("Invalid value length", len(value))

        self.value = value
        self.max_route_len = max_route_len

    @staticmethod
    def size(route_len: int) -> int:
        # Note that this is not one_step_size * route_len
        # because the information of the first mix node in the route doesn't need to be
        # encapsulated in a Sphinx packet.
        # A packet sender always know the address of the first mix node.
        return Filler.ONE_STEP_SIZE * (route_len - 1)

    @classmethod
    def build(cls, routing_keys: list[RoutingKeys], max_route_len: int) -> Self:
        if len(routing_keys) > max_route_len:
            raise ValueError("Too many routing keys", len(routing_keys))

        filler = b""
        # except the last key
        for routing_key in routing_keys[: len(routing_keys) - 1]:
            filler += zero_bytes(Filler.ONE_STEP_SIZE)

            # This process is the same as encrypting RoutingInformation to create EncryptedRoutingInformation,
            # so that a single filler can be easily reproduced and appended to the EncapsulatedRoutingInformation
            # when it is unwrapped.
            #
            # The implementation of the regular encryption can be found at the end of this file.
            rand = pseudo_random(routing_key.stream_cipher_key, max_route_len)
            assert len(filler) <= len(rand)
            # XOR with the last len(filler) bytes of rand
            filler = xor(filler, rand[len(rand) - len(filler) :])

        assert len(filler) == Filler.size(len(routing_keys))
        return cls(filler, max_route_len)


@dataclass
class EncryptedRoutingInformation:
    "An encrypted routing information using a private key of a certain mix node."

    value: bytes
    max_route_len: int

    def __init__(self, value: bytes, max_route_len: int):
        """Override the default constructor to check the size of value."""
        if len(value) != self.size(max_route_len):
            raise ValueError("Invalid value length", len(value))

        self.value = value
        self.max_route_len = max_route_len

    @staticmethod
    def size(max_route_len: int) -> int:
        # To make the size of Sphinx header constant, the size of this class is constant.
        return RoutingInformation.META_SIZE * max_route_len

    def truncate(self) -> TruncatedRoutingInformation:
        """
        Truncate the encrypted routing information as much as the size of a single filler.

        This method can be used when this routing information is about to be encapsulated once more.
        For more details, please see Filler.
        """
        return TruncatedRoutingInformation(
            self.value[: len(self.value) - Filler.ONE_STEP_SIZE], self.max_route_len
        )

    def unwrap(
        self, stream_cipher_key: bytes
    ) -> tuple[EncapsulatedRoutingInformation | None, NodeAddress]:
        """
        Decrypt the routing information and return a next node address and a next EncapsulatedRoutingInformation if exists.
        """
        # Since this EncryptedRoutingInformation has been truncated when being encapsulated,
        # add zero padding as much as the truncated bytes, before decrypting it.
        padding = zero_bytes(Filler.ONE_STEP_SIZE)
        decrypted = decrypt(self.value + padding, stream_cipher_key, self.max_route_len)

        flag = RoutingFlag(decrypted[0:FLAG_LENGTH])
        match flag:
            case RoutingFlag.ROUTING_FLAG_FORWARD_HOP:
                i = FLAG_LENGTH + VERSION_LENGTH
                node_address = decrypted[i : i + NODE_ADDRESS_LENGTH]
                i += NODE_ADDRESS_LENGTH + DELAY_LENGTH
                next_hop_integrity_mac = IntegrityHmac(
                    decrypted[i : i + IntegrityHmac.SIZE]
                )
                i += IntegrityHmac.SIZE
                encrypted_next_routing_info = EncryptedRoutingInformation(
                    decrypted[i:], self.max_route_len
                )
                return (
                    EncapsulatedRoutingInformation(
                        encrypted_next_routing_info, next_hop_integrity_mac
                    ),
                    node_address,
                )
            case RoutingFlag.ROUTING_FLAG_FINAL_HOP:
                i = FLAG_LENGTH + VERSION_LENGTH
                destination_address = decrypted[i : i + NODE_ADDRESS_LENGTH]
                i += NODE_ADDRESS_LENGTH
                _ = decrypted[i : i + SURB_IDENTIFIER_LENGTH]
                return (None, destination_address)


@dataclass
class TruncatedRoutingInformation:
    """
    Represent an encrypted routing information truncated as much as a single filler.
    """

    value: bytes

    def __init__(self, value: bytes, max_route_len: int):
        """Override the default constructor to check the size of value."""
        if len(value) != self.size(max_route_len):
            raise ValueError("Invalid value length", len(value))

        self.value = value

    @staticmethod
    def size(max_route_len: int) -> int:
        return EncryptedRoutingInformation.size(max_route_len) - Filler.ONE_STEP_SIZE


@dataclass
class FinalRoutingInformation:
    """
    Represent a forward-hop routing information not encrypted and not encapsulated
    """

    flag: RoutingFlag
    destination_address: NodeAddress

    # 52 bytes in total
    SIZE: int = (
        FLAG_LENGTH + VERSION_LENGTH + NODE_ADDRESS_LENGTH + SURB_IDENTIFIER_LENGTH
    )

    @classmethod
    def build(cls, destination: NodeAddress) -> Self:
        return cls(RoutingFlag.ROUTING_FLAG_FINAL_HOP, destination)

    def add_padding(
        self, route_len: int, max_route_len: int
    ) -> PaddedFinalRoutingInformation:
        """
        To make the final encrypted routing information (that will contain this routing information)
        have the same size as upper-layer encrypted routing information,
        add random-byte padding to the tail of FinalRoutingInformation.
        """
        padding = random_bytes(
            PaddedFinalRoutingInformation.padding_size(route_len, max_route_len)
        )
        return PaddedFinalRoutingInformation(
            self.flag.bytes()
            + VERSION
            + self.destination_address
            + SURB_IDENTIFIER
            + padding,
            max_route_len,
        )


@dataclass
class PaddedFinalRoutingInformation:
    """
    A random-byte padded FinalRoutingInformation
    """

    value: bytes
    max_route_len: int

    @staticmethod
    def padding_size(route_len: int, max_route_len: int) -> int:
        """
        The point of this padding is making the size of EncryptedRoutingInformation
        (that will contain this final routing information)
        the same as other EncryptedRoutingInformations that contain RoutingInformation.
        """
        return (
            EncryptedRoutingInformation.size(max_route_len)
            - Filler.size(route_len)
            - FinalRoutingInformation.SIZE
        )

    def encrypt(self, key: bytes) -> EncryptedPaddedFinalRoutingInformation:
        return EncryptedPaddedFinalRoutingInformation(
            encrypt(self.value, key, self.max_route_len)
        )


@dataclass
class EncryptedPaddedFinalRoutingInformation:
    value: bytes

    def combine_with_filler(self, filler: Filler) -> EncryptedRoutingInformation:
        """
        Because the size of this class is smaller than EncryptedRoutingInformation,
        add fillers to create EncryptedRoutingInformation from this value.
        """
        return EncryptedRoutingInformation(
            self.value + filler.value, filler.max_route_len
        )


AES128CTR_NONCE = zero_bytes(16)


def pseudo_random(key: bytes, max_route_len: int) -> bytes:
    """
    Return a pseudo-random bytes with length EncryptedRoutingInformation + a single filler
    generated using AES128-CTR with a constant nonce.
    """
    return aes128ctr(
        zero_bytes(
            EncryptedRoutingInformation.size(max_route_len) + Filler.ONE_STEP_SIZE
        ),
        key,
        AES128CTR_NONCE,
    )


def encrypt(data: bytes, key: bytes, max_route_len: int) -> bytes:
    """
    data is encrypted by XOR with a pseudo-random bytes generated using key,
    so that it can be decrypted later by XOR with the same pseudo-random bytes from the same key.
    """
    rand = pseudo_random(key, max_route_len)
    assert len(data) <= len(rand)
    return xor(data, rand[: len(data)])  # XOR with truncating rand


def decrypt(data: bytes, key: bytes, max_route_len: int) -> bytes:
    # Decryption is the same as encryption
    # because a common pseudo random value is used for XOR
    return encrypt(data, key, max_route_len)
