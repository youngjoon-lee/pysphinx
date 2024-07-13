# k in the Sphinx paper
SECURITY_PARAMETER = 16
# `r` in the Sphinx paper
# In this specification, the max number of mix nodes in a route is limited to this value.
DEFAULT_MAX_ROUTE_LENGTH = 6
# The length of node address which contains an IP address and a port.
NODE_ADDRESS_LENGTH = 2 * SECURITY_PARAMETER
# The length of flag that represents the type of routing information (forward-hop or final-hop)
FLAG_LENGTH = 1

VERSION_LENGTH = 3
VERSION = b"\x00\x00\x00"

# TODO: SURB is not supported for now, but the SURB identifier field in the Sphinx header remains for the consistency.
SURB_IDENTIFIER_LENGTH = SECURITY_PARAMETER
SURB_IDENTIFIER = b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"

# TODO: Delay is not supported for now, but the delay field in the Sphinx header remains for the consistency.
DELAY_LENGTH = 8
DELAY = b"\x00\x00\x00\x00\x00\x00\x00\x00"

# For the packet indistinguishability, the size of payload (padded) is a constant by default.
DEFAULT_PAYLOAD_SIZE = 1024
PAYLOAD_TRAILING_PADDING_INDICATOR = b"\x01"
DEFAULT_MAX_PLAIN_PAYLOAD_SIZE = (
    DEFAULT_PAYLOAD_SIZE - SECURITY_PARAMETER - len(PAYLOAD_TRAILING_PADDING_INDICATOR)
)
