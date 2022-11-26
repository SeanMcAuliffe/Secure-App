from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


# ------------------------------------------------------------------------------
def generate_static_keypair(username, password):
    """ Generates a new RSA keypair and saves it to disk, under the username
    and password provided. """
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_static_keypair(username, password):
    """ Loads a keypair from disk, using the username and password provided,
    to be loaded by the TerminalClient upon user authentication. """
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def generate_session_keypair():
    """ Generates a new asymmetric RSA keypair for use in a single session
    establishment ritual, does not save the keypair to disk. """
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def generate_symmetric_session_key():
    """ Generates a single-use shared key (symmetric, using Fernet) for
    use in a single message exhange. """
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def encrypt_message(message, key):
    """ Encryptes a message under the provided key using AES-256. """
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def decrypt_message(message, key):
    """ Decryptes a message under the provided key using AES-256. """
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sign_message(message, shared_session_key):
    """ Generates a hash of the key to sign the provided message. """
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def verify_signature(message, signature, shared_session_key):
    """ Verifies that the provided signature matches the hash of the
    shared key. """
    pass
# ------------------------------------------------------------------------------

# Below may be redundant, just use the genereic encrypt/decrpyt msg functions
# ------------------------------------------------------------------------------
def encrypt_session_key(session_key, recipient_public_key):
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def decrypt_session_key(session_key, recipient_private_key):
    pass
# ------------------------------------------------------------------------------

