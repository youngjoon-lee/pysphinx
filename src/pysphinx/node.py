from dataclasses import dataclass
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
)

# 32 bytes for a IP address and a port
NodeAddress: TypeAlias = bytes


@dataclass
class Node:
    public_key: X25519PublicKey
    addr: NodeAddress
