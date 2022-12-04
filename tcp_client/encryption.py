from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# The functions in this file have been adapted from the library documentation,
# See the sources below.
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
    if os.name == "nt":
        with open("tcp_client\\keys\\" + username + ".pem", "wb") as key_file:
            key_file.write(priv)
    else:
        with open("tcp_client/keys/" + username + ".pem", "wb") as key_file:
            key_file.write(priv)

    # Generate and store public key to file
    public_key = private_key.public_key()
    pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if os.name == "nt":
        with open("tcp_client\\keys\\" + username + ".pub", "wb") as key_file:
            key_file.write(pub)
    else:
        with open("tcp_client/keys/" + username + ".pub", "wb") as key_file:
            key_file.write(pub)

    # Generate symmetric key for encrypting message history, save it encrypted
    # under user static keys.
    symkey = os.urandom(32)
    iv = os.urandom(16)
    symkeyout = bytearray(48)
    symkeyout[0:32] = symkey
    symkeyout[32:48] = iv

    encrypted_symkey = asym_encrypt_message(bytes(symkeyout), public_key)

    if os.name == 'nt':
        with open("tcp_client\\keys\\" + username + ".sym", "wb") as key_file:
            key_file.write(encrypted_symkey)
    else:
        with open("tcp_client/keys/" + username + ".sym", "wb") as key_file:
            key_file.write(encrypted_symkey)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_static_symkey(username, password):
    """ Loads a keypair from disk, using the username and password provided,
    to be loaded by the TerminalClient upon user authentication. """
    input = None
    if os.name == "nt":
        with open("tcp_client\\keys\\" + username + ".sym", "rb") as key_file:
            input = key_file.read()
    else:
        with open("tcp_client/keys/" + username + ".sym", "rb") as key_file:
            input = key_file.read()
    # load the users saatic private key
    private_key = load_static_privkey(username, password)
    # decrypt the symket using the private key
    symkey = asym_decrypt_message(input, private_key)
    # unpack the key and the iv from the symkey
    key = symkey[0:32]
    iv = symkey[32:48]
    return key, iv
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_pubkey_from_bytes(key_bytes):
    """ Loads a public key from a byte string received over socket. """
    return serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def encode_pubkey_as_bytes(public_key):
    """ Encodes a public key as a byte string for transmission over socket. """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_pubkey_as_bytes(username):
    """ Encodes a public key as a byte string for transmission over socket. """
    public_key = None
    if os.name == "nt":
        with open("tcp_client\\keys\\" + username + ".pub", "rb") as key_file:
            public_key = key_file.read()
    else:
        with open("tcp_client/keys/" + username + ".pub", "rb") as key_file:
            public_key = key_file.read()
    return public_key
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_static_pubkey(username):
    """ Loads a keypair from disk, using the username and password provided,
    to be loaded by the TerminalClient upon user authentication. """
    public_key = None
    if os.name == "nt":
        with open("tcp_client\\keys\\" + username + ".pub", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    else:
        with open("tcp_client/keys/" + username + ".pub", "rb") as key_file:
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
    if os.name == "nt":
        with open("tcp_client\\keys\\" + username + ".pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode(),
            backend=default_backend()
        )
    else:
        with open("tcp_client/keys/" + username + ".pem", "rb") as key_file:
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
    establishment ritual, does not save the keypair to disk. Also returns
    the parameter numbers used to generate the keypair, which also need to
    be sent to the recipient. """
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    parameter_numbers = parameters.parameter_numbers()
    return private_key, public_key, parameter_numbers.p, parameter_numbers.g
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def generate_session_keypair_from_numbers(p, g, y):
    """ Generates a new asymmetric RSA keypair for use in a single session
    establishment ritual, does not save the keypair to disk. Also returns
    the parameter numbers used to generate the keypair, which also need to
    be sent to the recipient. """
    pn = dh.DHParameterNumbers(p, g)
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    parameters = pn.parameters()
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, peer_public_numbers.public_key()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def derive_shared_key(local_private_key, peer_public_key):
    """ Generates a single-use shared key (symmetric, using Fernet) for
    use in a single message exhange. """
    shared_key = local_private_key.exchange(peer_public_key)
    # TODO: What is derivation for
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'expelliarmus',
    ).derive(shared_key)
    return derived_key
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def asym_encrypt_message(message: bytes, key):
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
def asym_decrypt_message(message, key):
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
def pad_message(message):
    """ Pads a message to a multiple of 16 bytes, required for AES 
    encryption. """
    return message + "\0" * (16 - len(message) % 16)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def pad_message_bytes(message):
    """ Pads a message to a multiple of 16 bytes, required for AES 
    encryption. """
    return message + b"\0" * (16 - len(message) % 16)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def remove_padding_bytes(message):
    """ Removes padding from a message. """
    return message.rstrip(b"\0")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sym_encrypt_message(message: bytes, key):
    """ Encryptes a message encoded as bytes under the provided key. """
    message = pad_message(message).encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return cipher_text, iv
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sym_iv_encrypt_message(message: bytes, key, iv):
    """ Encryptes a message encoded as bytes under the provided key and IV. """
    message = pad_message_bytes(message)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return cipher_text
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sym_decrypt_message(message, key, iv):
    """ Decryptes a message under the provided key, must be the corresponding
    key to the one used to encrypt the message. """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_message = decryptor.update(message) + decryptor.finalize()
    return plaintext_message.decode()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sym_decrypt_message_rm_padding(message, key, iv):
    """ Decryptes a message under the provided key, must be the corresponding
    key to the one used to encrypt the message. """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_message = decryptor.update(message) + decryptor.finalize()
    plaintext_message = remove_padding_bytes(plaintext_message)
    return plaintext_message.decode()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def sign_message(message, private_key):
    """ Generates a hash of the key and signs the provided message. """
    signature = private_key.sign(
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
def verify_signature(message, signature, public_key):
    """ Verifies that the provided signature matches the hash of the
    shared key. """
    shared_public = public_key.public_key()
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
