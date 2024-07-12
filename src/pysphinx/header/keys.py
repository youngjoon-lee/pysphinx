from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pysphinx.node import Node


@dataclass
class KeyMaterial:
    """
    Contain a list of RoutingKeys for all mix nodes in the route,
    and a shared secret that will be contained in a SphinxHeader for the first mix node in the route.
    """

    initial_ephemeral_pubkey: X25519PublicKey
    routing_keys: list[RoutingKeys]

    @classmethod
    def derive(
        cls, initial_ephemeral_privkey: X25519PrivateKey, route: list[Node]
    ) -> Self:
        """
        Derive KeyMaterial for route using initial_ephemeral_privkey provided.
        """
        initial_ephemeral_pubkey = initial_ephemeral_privkey.public_key()

        routing_keys: list[RoutingKeys] = []
        accumulated_privkey = initial_ephemeral_privkey
        for node in route:
            dh_shared_key = accumulated_privkey.exchange(node.public_key)
            node_routing_keys = RoutingKeys.derive(dh_shared_key)

            # TODO: find a proper library for Ristretto operations
            # https://github.com/youngjoon-lee/pysphinx/issues/2
            #
            # https://github.com/nymtech/sphinx/blob/ca107d94360cdf8bbfbdb12fe5320ed74f80e40c/src/header/keys.rs#L128-L128
            # blinding_factor_scalar = Scalar.from_bytes_mod_order(node_routing_keys.blinding_factor)
            # accumulated_privkey = product(accumulated_privkey, blinding_factor_scalar)

            routing_keys.append(node_routing_keys)

        return cls(initial_ephemeral_pubkey, routing_keys)

    @staticmethod
    def blind_shared_pubkey(
        shared_pubkey: X25519PublicKey, blinding_factor: bytes
    ) -> X25519PublicKey:
        """
        Blind shared_pubkey to derive a next public key.
        """
        # TODO: find a proper library for Ristretto operations
        # https://github.com/youngjoon-lee/pysphinx/issues/2
        #
        # https://github.com/nymtech/sphinx/blob/ca107d94360cdf8bbfbdb12fe5320ed74f80e40c/src/header/mod.rs#L236-L236
        # For now, we're skipping blinding because we don't accumulate a private key using blinding factor
        # when deriving RoutingKeys.
        return shared_pubkey


# Adopted from https://github.com/nymtech/sphinx/blob/ca107d94360cdf8bbfbdb12fe5320ed74f80e40c/src/constants.rs#L26-L26
HKDF_INPUT_SEED = b"Dwste mou enan moxlo arketa makru kai ena upomoxlio gia na ton topothetisw kai tha kinisw thn gh."


@dataclass
class RoutingKeys:
    """
    Contain all keys for a mix node in the route.
    """

    # For Sphinx header encryption (AES-128)
    stream_cipher_key: bytes
    # For HMAC integrity authentication
    header_integrity_hmac_key: bytes
    # For payload encryption (ChaCha20)
    payload_key: bytes
    # For deriving a shared key for a next mix node, combining with the previous ephemeral private key
    blinding_factor: bytes

    @classmethod
    def derive(cls, dh_shared_key: bytes) -> Self:
        """
        Derive all keys from dh_shared_key using HKDF-SHA256.
        """
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=256, salt=None, info=HKDF_INPUT_SEED
        ).derive(dh_shared_key)
        assert len(derived_key) == 256

        stream_cipher_key = derived_key[0:16]  # 16bytes == 128bits
        header_integrity_hmac_key = derived_key[16:32]  # 16bytes
        payload_key = derived_key[32:224]  # 192bytes
        blinding_factor = derived_key[224:]  # 32bytes
        return cls(
            stream_cipher_key, header_integrity_hmac_key, payload_key, blinding_factor
        )
