from cryptography.fernet import Fernet


class Session:
    """ Stores information about a single session key that has been
    established. The session key is used to encrypt and decrypt
    messages between peers. It is valid only for a single message and
    then is destroyed."""
    def __init__(self, local_ip, local_port, remote_ip, remote_port):
        self.recipient_ip = remote_ip
        self.recipient_port = remote_port
        self.sender_ip = local_ip
        self.sender_port = local_port
        self.local_public_key = None
        self.local_private_key = None
        self.shared_session_key = None
