from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


# ------------------------------------------------------------------------------
def generate_static_keypair(username, password):
    """ Generates a new RSA keypair and saves it to disk, under the username
    and password provided."""
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_static_keypair(username, password):
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def generate_session_keypair():
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def generate_session_key():
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def encrypt_message(message, key):
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def decrypt_message(message, key):
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sign_message(message, private_key):
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def verify_signature(message, signature, public_key):
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def encrypt_session_key(session_key, recipient_public_key):
    pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def decrypt_session_key(session_key, recipient_private_key):
    pass
# ------------------------------------------------------------------------------

