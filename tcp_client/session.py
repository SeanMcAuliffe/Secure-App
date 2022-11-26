class Session:
    """ Stores information about a single session key that has been
    established. The session key is used to encrypt and decrypt
    messages between peers. It is valid only for a single message and
    then is destroyed."""
    def __init__(self):
        self.key = None
        self.recipient = None
        self.recipient_ip = None
        self.recipient_public_key = None
        self.sender = None
        self.sender_ip = None
        self.sender_public_key = None