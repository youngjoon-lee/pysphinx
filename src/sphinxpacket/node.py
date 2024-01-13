from dataclasses import dataclass
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# 32 bytes for a IP address and a port
NodeAddress: TypeAlias = bytes


@dataclass
class Node:
    private_key: X25519PrivateKey
    addr: NodeAddress

    def public_key(self) -> X25519PublicKey:
        return self.private_key.public_key()
