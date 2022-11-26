from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/

# ------------------------------------------------------------------------------
def generate_static_keypair(username, password):
    """ Generates a new RSA keypair and saves it to disk, under the username
    and password provided. The password needs to be provided in order to load
    the keypair later. """

    # Generate and store private key to file
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    priv = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    filename = "./keys/" + username + ".pem"
    with open(filename, "wb") as f:
        f.write(priv)

    # Generate and store public key to file
    public_key = private_key.public_key()
    pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    filename = "./keys/" + username + ".pub"
    with open(filename, "wb") as f:
        f.write(pub)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_static_pubkey(username):
    """ Loads a keypair from disk, using the username and password provided,
    to be loaded by the TerminalClient upon user authentication. """
    public_key = None
    with open("./keys/" + username + ".pub", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_static_privkey(username, password):
    """ Loads a keypair from disk, using the username and password provided,
    to be loaded by the TerminalClient upon user authentication. """
    private_key = None
    with open("./keys/" + username + ".pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode(),
            backend=default_backend()
        )
    return private_key
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def generate_session_keypair():
    """ Generates a new asymmetric RSA keypair for use in a single session
    establishment ritual, does not save the keypair to disk. """
    # TODO: Do the parameters need to be shared between the two peers?
    # Should the server store them? If cryptography problems occur, try this.
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def generate_shared_key(local_private_key, peer_public_key):
    """ Generates a single-use shared key (symmetric, using Fernet) for
    use in a single message exhange. """
    shared_key = local_private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'expelliarmus',
    ).derive(shared_key)
    return derived_key
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def encrypt_message(message: bytes, key):
    """ Encryptes a message encoded as bytes under the provided key. """
    encrypt_message = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypt_message
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def decrypt_message(message, key):
    """ Decryptes a message under the provided key, must be the corresponding
    key to the one used to encrypt the message. """
    plaintext_message = key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext_message
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sign_message(message, shared_session_key):
    """ Generates a hash of the key and signs the provided message. """
    signature = shared_session_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def verify_signature(message, signature, shared_session_key):
    """ Verifies that the provided signature matches the hash of the
    shared key. """
    shared_public = shared_session_key.public_key()
    try:
        shared_public.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True
# ------------------------------------------------------------------------------
