from pysphinx.const import DEFAULT_MAX_PATH_LENGTH, DEFAULT_MAX_PLAIN_PAYLOAD_SIZE


class Config:
    """
    The global configuration used throughout this package
    """

    # The maximum length of mix path that the user can specify when creating a Sphinx packet.
    # Even if the user specifies less shorter path,
    # padding is added to ensure that all Sphinx packets have the uniform size.
    # This padding is not distinguishable by mix nodes.
    # In other words, mix nodes cannot know how many mix nodes the user specified in the path.
    # If the user specifies a longer path than this value, an error is raised.
    max_path_length = DEFAULT_MAX_PATH_LENGTH
    # The maximum size of message that can be wrapped in a Sphinx packet
    # Shorter messages will be padded to this size
    # to ensure that all Sphinx packets have the uniform size.
    # Messages longer than this size will raise an error.
    max_message_size = DEFAULT_MAX_PLAIN_PAYLOAD_SIZE

    @classmethod
    def set_max_path_length(cls, length: int) -> None:
        if length <= 0:
            raise ValueError("The max path length must be greater than 0")
        cls.max_path_length = length

    @classmethod
    def set_max_message_size(cls, size: int) -> None:
        if size <= 0:
            raise ValueError("The max message size must be greater than 0")
        cls.max_message_size = size

    @classmethod
    def reset(cls) -> None:
        cls.max_path_length = DEFAULT_MAX_PATH_LENGTH
        cls.max_message_size = DEFAULT_MAX_PLAIN_PAYLOAD_SIZE
