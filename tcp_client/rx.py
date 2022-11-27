import zmq
import random
from os import urandom
import requests
import json
import encryption

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
        self.port = random.randint(49152, 65535)
        context = zmq.Context()
        self.rx = context.socket(zmq.REP)
        self.rx.bind(f"tcp://*:{self.port}")
        self.session_key = None
        self.buffer = buffer
        self.username = None
        self.password = None
        self.cookie = None
        self.ongoing = False
        self.authenticated = False
        self.accepting_handshake = False
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
    def start(self):
        if not self.authenticated:
            print("User must be authenticated before the Rx thread can start.")
            return

        while self.ongoing:
            # Wait for the next request from a peer
            incoming_msg = self.rx.recv().split(b" ")

            # Determine the type of message and call appropriate handler
            if incoming_msg[0] == b"challenge":
                if self.session_key is not None:
                    self.accept_session(incoming_msg[1:])
                else:
                    raise RuntimeError("Received challenge when session \
                                        already established")
            elif incoming_msg[0] == b"handshake":
                if not self.accepting_handshake:
                    raise RuntimeError("Received handshake when not \
                                        accepting handshakes")
                else:
                    self.complete_handshake(incoming_msg[1:])
            elif incoming_msg[0] == b"message":
                if self.session_key is None:
                    self.rx_buffer.add_msg(incoming_msg[1:])
                else:
                    raise RuntimeError("Message received but session key \
                                        not established")
            else:
                raise RuntimeError("Received unrecognized message type")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def stop(self):
        self.authenticated = False
        self.ongoing = False
        self.rx.close()
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
        N = challenge[1]
        # 3 Encrypt M under the sender's public key
        M = urandom(32)

        # 1.
        r = self.http_request("GET", "create_session",
                              {"recipient_username": sender})
        if r is not None and r.status_code == 200:
            sender_data = json.loads(r.json)
            sender_ip = sender_data["ip"]
            sender_port = str(sender_data["port"])
            sender_pubkey = sender_data["pubkey"]
        else:
            raise RuntimeError("Failed to send message; could not find \
                                recipient IP.")

        # 2.
        local_privkey = encryption.load_static_privkey(self.username, self.password)
        decrypted_N = encryption.decrypt_message(N, local_privkey)

        # 3.
        pubkey = encryption.load_pubkey_from_bytes(sender_pubkey)
        encrypted_M = encryption.encrypt_message(M, pubkey)

        # 4. Send response to sender
        response = b"response " + self.username.encode() + b" " + decrypted_N + encrypted_M
        self.rx.send(response)
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def complete_handshake(self, handshake):
        pass
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def receive_message(self, msg):
        """ Handles the process of receiving a message from a remote peer
        client. """
        self.rx.send(b"ok")

    # --------------------------------------------------------------------------