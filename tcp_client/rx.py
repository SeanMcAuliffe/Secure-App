import zmq
import random
from os import urandom
import requests
import json
import encryption
from base64 import b64encode, b64decode

SERVER_IP = "127.0.0.1:5000"


class RxSocket:
    """ Class for a thread that listens for incoming messages
    from other peers. The thread is responsible for receiving
    session establishment challenges from peers, and completing
    the session estalibhsment process. Once a session is established,
    the thread is responsible for receiving a chat message from the
    peer and placing it in the shared message buffer with the main
    thread. """
    # --------------------------------------------------------------------------
    def __init__(self, buffer):
        """ Creates a new zmq REP socket and binds it to a 
        random port. """
        self.context = zmq.Context()
        self.rx = self.context.socket(zmq.REP)
        self.port = self.rx.bind_to_random_port(f"tcp://*", min_port=49152, max_port=65535)
        self.session_key = None
        self.buffer = buffer
        self.username = None
        self.password = None
        self.cookie = None
        self.ongoing = False
        self.authenticated = False
        self.phase = 0
        self.peer_pubkey = None
        self.monce = None # M nonce
        self.sender_username = None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def http_request(self, method, endpoint, data=None):
        # TODO: Encrypt all json data sent to the server
        """ Wrapper to send an HTTP request to the server. """
        url = f"http://{SERVER_IP}/{endpoint}"
        data = json.dumps(data, indent=4)
        if self.cookie is None:
            headers={"Content-Type":"application/json"}
        else:
            headers={"Content-Type":"application/json",
                     "Cookie": self.cookie}
        try:
            if method == "GET":
                r = requests.get(url, headers=headers)
            elif method == "POST":
                r = requests.post(url, json=data, headers=headers)
            else:
                raise ValueError("Invalid HTTP method.")
        except requests.exceptions.ConnectionError:
            print("Could not connect to SecureChat™ server.")
            return None
        return r
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def add_credentials(self, username, password, cookie):
        self.username = username
        self.password = password
        self.cookie = cookie
        self.authenticated = True
        self.ongoing = True
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def run(self):
        if not self.authenticated:
            print("User must be authenticated before the Rx thread can start.")
            return

        while self.ongoing:
            # Wait for the next request from a peer
            try:
                incoming_msg = self.rx.recv(flags=zmq.NOBLOCK).split(b" ")
            except zmq.ZMQError:
                continue
            # Determine the type of message and call appropriate handler
            if incoming_msg[0] == b"challenge":
                if self.phase == 0:
                    self.accept_session(incoming_msg[1:])
                else:
                    self.rx.send(b"Fatal error.")
                    raise RuntimeError("Received challenge in wrong order.")

            elif incoming_msg[0] == b"handshake":
                if not int(self.phase) != 1:
                    #self.rx.send(b"Fatal error.")
                    # raise RuntimeError("Received handshake out of phase. Phase: " + str(self.phase))
                    print(f"Phase should be 1, but phase is {self.phase}")
                    self.complete_handshake(incoming_msg[1:])
                else:
                    self.complete_handshake(incoming_msg[1:])

            elif incoming_msg[0] == b"generate_session_key":
                if self.phase != 2:
                    self.rx.send(b"Fatal error.")
                    raise RuntimeError("Session key generation request came out of order")
                else:
                    self.generate_session_key(incoming_msg[1:])

            elif incoming_msg[0] == b"message":
                if self.phase != 3:
                    self.rx.send(b"Fatal error.")
                    raise RuntimeError("Message received but session key \
                                        not established")
                else:
                    self.receive_message(incoming_msg[1:])

            else:
                self.rx.send(b"Fatal error.")
                raise RuntimeError(f"Received unrecognized message type {incoming_msg[0]}")
        self.rx.close()
        self.context.term()
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def stop(self):
        self.ongoing = False
        self.authenticated = False
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def accept_session(self, challenge):
        """ Handles the process of establishing a secure session when
        initated by a remote peer client. The establish_session() method
        in TerminalChat initiates the session handhshake process when a
        peer client sends a message. """
        # 1. we will need to get the sender's public key from server
        sender = challenge[0]
        # 2. we need to decrypt N with local private key
        N = b64decode(challenge[1])
        # 3 Encrypt M under the sender's public key
        self.monce = urandom(32)

        # 1.
        r = self.http_request("POST", "create_session",
                              {"recipient_username": sender.decode()})
        if r is not None and r.status_code == 200:
            sender_data = r.json()
            sender_pubkey = sender_data["pubkey"].encode()
            self.sender_username = sender
        else:
            print(r)
            raise RuntimeError("Failed to send message; could not find recipient IP.")

        # 2.
        local_privkey = encryption.load_static_privkey(self.username, self.password)
        decrypted_N = encryption.decrypt_message(N, local_privkey)
        print(f"nonce 2: {decrypted_N}")

        # 3.
        pubkey = encryption.load_pubkey_from_bytes(sender_pubkey)
        encrypted_M = encryption.encrypt_message(self.monce, pubkey)

        # 4. Send response to sender
        response = b"response " + self.username.encode() + b" " + b64encode(decrypted_N) + b" " + b64encode(encrypted_M)
        self.rx.send(response)
        self.phase = 1
        print("Receiving thread has process challenge and responded.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def complete_handshake(self, handshake):
        recieved_monce = b64decode(handshake[0])
        if recieved_monce != self.monce:
            raise RuntimeError("Sender failed authentication challenge")
        self.rx.send(b"handshake_success")
        self.phase = 2
        # This completes two-way authentication
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def generate_session_key(self, handshake):
        peer_pubkey_bytes = b64decode(handshake[0])
        peer_pubkey = encryption.load_pubkey_from_bytes(peer_pubkey_bytes)
        local_privkey, local_pubkey = encryption.generate_session_keypair()
        local_pubkey_bytes = encryption.encode_pubkey_as_bytes(local_pubkey)
        self.session_key = encryption.derive_shared_key(local_privkey, peer_pubkey)
        self.rx.send(b"agreed " + b64encode(local_pubkey_bytes))
        self.phase = 3
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def receive_message(self, msg):
        """ Handles the process of receiving a message from a remote peer
        client. """
        encrypted_msg = b64decode(msg[0])
        signature = b64decode(msg[1])
        decrypted_msg = encryption.decrypt_message(encrypted_msg, self.session_key)
        valid_signature = encryption.verify_signature(decrypted_msg, signature)
        if not valid_signature:
            raise RuntimeError("Message was recieved under valid session, with \
                                invalid signature.")
        msg_to_save = self.sender_username + " " + decrypted_msg.decode()
        self.buffer.semaphore.acquire()
        self.buffer.add_msg(msg_to_save)
        self.buffer.semaphore.release()
        self.rx.send(b"ok")
        self.sender_username = None
        self.peer_pubkey = None
        self.session_key = None
        self.monce = None
        self.phase = 0
    # --------------------------------------------------------------------------