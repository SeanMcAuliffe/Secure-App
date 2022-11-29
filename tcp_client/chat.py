import requests
import os
import json
from cache import ChatCache
import encryption
import threading
from base64 import b64encode, b64decode

SERVER_IP = "127.0.0.1:5000"


class TerminalChat:
    """ TerminalChat serves as the main thread which presents
    a REPL for the user to interact with the terminal chat app,
    and it prints the UI in response to state changes. """

    # --------------------------------------------------------------------------
    def __init__(self, tx, msg_buffer, rx_socket, host_ip):
        self.tx = tx # zmq socket for transmitting messages
        self.msg_buffer = msg_buffer # wrapper around a LIFO queue
        self.rx_socket = rx_socket
        self.rx_thread = threading.Thread(target=self.rx_socket.run)
        self.host_ip = host_ip
        self.ongoing = True
        self.username = None
        self.password = None
        self.cookie = None
        self.authenticated = False # is user logged in?
        # Stores chat_id (int) of active chat within msg_history
        self.active_chat = None
        # Stores ChatCache Object for all chats
        self.cache = None
        self.session_key = None
        self.commands = {
            "new_account": self.create_account,
            "login": self.login,
            "logout": self.logout,
            "delete_account": self.delete_account,
            "delete_msg": self.delete_msg,
            "delete_chat": self.delete_chat,
            "list": self.list_chats,
            "new_chat": self.create_chat,
            "open": self.open_chat,
            "close": self.close_chat,
            "send": self.send_message,
            "help": self.ui_help,
            "exit": self.exit_client
        }
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    @staticmethod
    def clear_screen() -> None:
        if os.name == 'nt':
            _ = os.system('cls')
        else:
            _ = os.system('clear')
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
    def create_account(self, args):
        """ Populates data for HTTP request to create a new
        account on the server, prints result of operation."""
        self.clear_screen()
        print("*** Create a New Account ***")
        try:
            username = input("Username: ")
            password = input("Password: ")
            password2 = input("Confirm Password: ") 
            while password != password2:
                password2 = input("Confirm Password: ")
                print("Passwords do not match, try again.")
        except KeyboardInterrupt:
            return
        encryption.generate_static_keypair(username, password)
        public = encryption.load_pubkey_as_bytes(username).decode()
        data = {"username": username, "password": password, "pubkey": public}
        r = self.http_request("POST", "register", data)
        if r is not None and r.status_code == 200:
            print("Account created successfully.")
        elif r is not None and r.status_code != 200:
            print("Account creation failed.")
            print(r.text)
            # Todo; if failed, delete the keypair
        else:
            print("Server connection failed.")
            # Todo; if failed, delete the keypair
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def login(self, args):
        """ Populates data for HTTP request to login to the
        server, prints result of operation. """
        self.clear_screen()
        print("*** Login to SecureChat™ ***")
        try:
            username = input("Username: ")
            password = input("Password: ")
        except KeyboardInterrupt:
            return
        # TODO: Make sure that server saves network location upon login
        data = {"username": username, "password": password,
                "ip": self.host_ip, "port": self.rx_socket.port}
        r = self.http_request("POST", "login", data)
        if r is not None and r.status_code == 200:
            print("Login successful.")
            self.authenticated = True
            self.username = username
            self.password = password
            cookie = r.headers["Set-Cookie"]
            end = cookie.find(';', 0)
            self.cookie = cookie[0:end]
            # Check if username.json exists, if not create it
            # if yes, load message history into memory
            self.load_messages()
            # Start listening for incoming messages for the user
            self.rx_socket.add_credentials(username, password, self.cookie)
            self.rx_thread.start()
        elif r is not None and r.status_code != 200:
            print("Login failed.")
            self.authenticated = False
            self.cookie = None
            print(r.text)
        else:
            print("Server connection failed.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def logout(self, args):
        """ Sends a request to the server to log out the user.
        Triggers the client to save the message history to disk
        and exit. """
        r = self.http_request("GET", "logout")
        if r is not None and r.status_code == 200:
            print("Logout successful.")
            self.authenticated = False
            self.active_chat = None
            self.cookie = None
            self.save_messages() # TODO: Think about where save should happen
            self.rx_socket.stop()
            self.rx_thread.join()
            self.exit_client(None)
        elif r is not None and r.status_code != 200:
            print("Logout failed.")
            print(r.text)
        else:
            print("Server connection failed.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def delete_account(self, args):
        """Sends a request to the server to delete
        the currently logged-in user account."""
        self.clear_screen()
        print("*** Delete Account ***")
        try:
            password = input("Password: ")
            if password != self.password:
                print("Incorrect password.")
                return
            print("Are you sure you wish to proceed? y/n")
            confirm = input("> ")
            if confirm != "y":
                return
        except KeyboardInterrupt:
            return
        r = self.http_request("GET", "delete_account")
        if r is not None and r.status_code == 200:
            print("Account deleted successfully.")
            self.authenticated = False
            self.cookie = None
        elif r is not None and r.status_code != 200:
            print("Account deletion failed.")
            print(r.text)
        else:
            print("Server connection failed.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def delete_msg(self, args):
        if not self.authenticated:
            print("You must be logged in to delete messages.")
            return
        try:
            msg_id = int(args[0])
        except (IndexError, ValueError):
            print("Invalid message ID.")
            return
        if self.active_chat is None:
            print("No chat is currently open.")
            return
        rc = self.cache.delete_message(self.active_chat, msg_id)
        if rc:
            print("Message deleted successfully.")
        else:
            print("Message deletion failed.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def delete_chat(self, args):
        if not self.authenticated:
            print("You must be logged in to delete chats.")
            return
        try:
            chat_id = int(args[0])
        except (IndexError, ValueError):
            print("Invalid chat ID.")
            return
        if not self.cache.chat_exists(chat_id):
            print("Chat does not exist.")
            return
        if self.active_chat == chat_id:
            self.active_chat = None
        rc = self.cache.delete_chat(chat_id)
        if rc:
            print("Chat deleted successfully.")
        else:
            print("Chat deletion failed.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def list_chats(self, args):
        if not self.authenticated:
            print("You must be logged in to list chats.")
            return
        print(self.cache.list())
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def create_chat(self, args):
        if not self.authenticated:
            print("You must be logged in to create chats.")
            return
        try:
            recipient = str(args[0])
        except (IndexError, ValueError):
            print("Invalid recipient.")
            return
        rc = self.cache.new_chat(recipient)
        if not rc:
            print("Failed to create chat.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def open_chat(self, args):
        """ Attempts to open a chat with the provided ID,
        sets the active_chat field to the ID if successful. """
        if not self.authenticated:
            print("You uyst be logged in to open a chat.")
            return
        try:
            chat_id = int(args[0])
        except (IndexError, ValueError):
            print("Invalid chat ID.")
            return
        if not self.cache.chat_exists(chat_id):
            print("Chat does not exist.")
            return
        self.active_chat = chat_id
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def close_chat(self, args):
        """ Sets the active chat to None, this prevents the chat
        from being displayed in the UI, and prevents the user from
        querying or modifying the chat. """
        self.active_chat = None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def establish_session(self, peer_static_pubkey):
        """ Handles the process of establishing a secure session when
        initated locally by the user. The counterpart to this function
        is the accept_session() function in the RxSocket thread, which
        handles the process of completeting the challenge and generating
        the session key. """
        
        # This should be none at the beginning of a new session
        if self.session_key is not None:
            print("Warning: session key was not destroyed after last use.")
            self.session_key = None
        
        # STEP ONE: AUTHENTICATE NETWORK LOCATION IS CONTROLLED BY USER
        # 1. Encrypt a random nonce with the peers static public key
        nonce = os.urandom(32)
        peer_pubkey = encryption.load_pubkey_from_bytes(peer_static_pubkey)
        encrypted_nonce = encryption.encrypt_message(nonce, peer_pubkey)

        # 2. Send the encrypted nonce to the peer with our user name
        # so that they can also verify us
        msg = b"challenge " + self.username.encode() + b" " + b64encode(encrypted_nonce)
        self.tx.send(msg)

        # 3. Receive decrypted nonce from peer, verify, receieve challenge
        # TODO: There is a problem here, the socket is blocking,
        # so if the peer never responds, this will hang forever
        # Look into this https://pyzmq.readthedocs.io/en/latest/api/zmq.html#poller
        resp = self.tx.recv().split(b" ")
        # Response is of the form: "response <username> <decrypted N> <encrypted M>"
        if len(resp) != 4:
            print("Invalid response from peer.")
            return
        if resp[0] != b"response":
            print("Invalid response from peer.")
            return
        if resp[1] != self.cache.active_user(self.active_chat).encode():
            print("Response from invalid peer.")
            return
        if b64decode(resp[2]) != nonce:
            print("Peer failed to decrypt nonce.")
            return

        # 4. Decrypt challenge, M, with private key and send back to peer
        local_privkey = encryption.load_static_privkey(self.username, self.password)
        decrypted_challenge = encryption.decrypt_message(b64decode(resp[3]), local_privkey)
        self.tx.send(b"handshake " + b64encode(decrypted_challenge))
        handshake_resp = self.tx.recv()
        if handshake_resp != b"handshake_success":
            print("Handshake failed.")
            return
        
        # At this point both peers are authenticated to each other

        # STEP TWO: GENERATE NEW SESSION KEY PAIR AND DERIVE SHARED KEY
        # 1. Generate local session keypair, save parameters used to generate
        session_priv, session_pub, prime, generator = encryption.generate_session_keypair()
        public_number = session_pub.public_numbers().y

        session_pubkey_bytes = encryption.encode_pubkey_as_bytes(session_pub)

        # 2. Send peer cmd to generate session keypair, provide our parameters

        # 2. Receive new session public key of peer
        self.tx.send(b"generate_session_key " +
                    b64encode(prime) + b" " +
                    b64encode(generator) + b" " +
                    b64encode(public_number))
    
        # Receive response indicating success
        session_response = self.tx.recv().split(b" ")
        if len(session_response) != 2:
            print("Invalid response from peer.")
            return
        if session_response[0] != b"agreed ":
            print("Invalid response from peer.")
            return
        
        # Derive shared key
        peer_session_pub = encryption.load_pubkey_from_bytes(b64decode(session_response[1]))
        # 3. Derive shared key from local session private key and peer session public key
        self.session_key = encryption.derive_shared_key(session_priv, peer_session_pub)
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def receive_message(self):
        """ Handles incoming chat messages from the buffer. Messages have already
        been authenticated and decrypted by RxSocket thread, so this function
        only needs to pass them on to the local cache. """
        if self.msg_buffer.is_empty():
            return
        # msg is of form "<sender> <msg>"
        self.buffer.semaphore.acquire()
        msg = self.msg_buffer.get_msg()
        self.buffer.semaphore.release()
        delimiter = msg.find(" ")
        sender = msg[0:delimiter]
        msg = msg[delimiter+1:]
        self.cache.add_message_by_username(sender, msg)
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def send_message(self, args):
        """ 1. Get recipient IP address from server (future improvement, cache IP)
        2. If recipient unavailable, print error and return
        3. Begin Session Establishment challenge
        4. If challenge fails, print error and return
        5. Encrypt message with session key
        6. Sign message with session key hash
        7. Send message to recipient
        8. Delete session key
        9. Add sent message to local cache of chat history """
        msg = "".join(args)
        recipient = self.cache.active_user(self.active_chat)
        if recipient is None:
            print("Invalid recipient.")
            return
        # Get recipient IP + port from server
        r = self.http_request("POST", "create_session",
                              {"recipient_username": recipient})
        if r is not None and r.status_code == 200:
            recipient_data = r.json()
            recipient_ip = recipient_data["ip"]
            recipient_port = str(recipient_data["port"])
            recipient_pubkey = recipient_data["pubkey"].encode()
        else:
            print("Failed to send message; could not find recipient IP.")
            return
        # Challenge recipient to establish session
        self.tx.connect(f"tcp://{recipient_ip}:{recipient_port}")
        self.establish_session(recipient_pubkey)
        if self.session_key is None:
            print("Failed to send message; could not establish session.")
            self.session_key = None
            self.tx.disconnect(f"tcp://{recipient_ip}:{recipient_port}")
            return
        # Encrypt message under session key
        encrypted_msg = encryption.encrypt_message(msg, self.session_key)
        # Sign message with session key hash
        signature = encryption.sign_message(encrypted_msg, self.session_key)
        # Send message to recipient
        self.tx.send(b"message " + b64encode(encrypted_msg) + b" " + b64encode(signature))
        resp = self.tx.recv()
        if resp != b"ok":
            print(f"Message was not delivered to {recipient}.")
        # Delete session key
        self.session_key = None
        # Add sent message to local cache of chat history
        rc = self.cache.add_message_by_id(self.active_chat, self.username, msg)
        if not rc:
            print("Failed to add message to cache.")
        self.session_key = None
        self.tx.disconnect(f"tcp://{recipient_ip}:{recipient_port}")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def load_messages(self):
        """ Loads message history from JSON non-volatile storage
        into memory and decrypts it. Message history is stored on
        disk by username, and is only retrievable after a user has
        authenticated with the server. """
        if os.name == "nt":
            filename = "tcp_client\\chats\\" + self.username + ".json"
        else:
            filename = "tcp_client/chats/" + self.username + ".json"
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                # TODO: Decrypt messages
                self.cache = ChatCache(json.load(f))
        else:
            self.cache = ChatCache()
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def save_messages(self):
        """ When user logs out, or client exits, encrypt and save
        message history changes that have accumulated to the disk. """
        if os.name == "nt":
            filename = "tcp_client\\chats\\" + self.username + ".json"
        else:
            filename = "tcp_client/chats/" + self.username + ".json"
        with open(filename, "w") as f:
            # TODO: Encrypt messages
            f.write(json.dumps(self.cache.history))
    # --------------------------------------------------------------------------

    def display_UI(self):
        """ Print the state of the TerminalChat to the user. """
        if self.authenticated:
            print(f"\nUser: {self.username}")
        else:
            print("\nUser: None")
        if self.active_chat is not None:
            print(f"Active Chat: {self.cache.header_by_id(self.active_chat)}")
            print(self.cache.display_chat(self.active_chat))
        else:
            print("Active Chat: None")

    # --------------------------------------------------------------------------
    def ui_help(self, args):
        print(self.commands.keys())
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def exit_client(self, args):
        self.ongoing = False
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def parse_command(self):
        """ Parses a command from the user and executes it. """
        command_string = input(">> ").split(' ')
        cmd = command_string[0]
        args = command_string[1:]
        if cmd in self.commands:
            self.commands[cmd](args)
        else:
            print("Invalid command.")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def run(self):
        self.clear_screen()
        """ REPL for the TerminalChat UI. """
        print("***  Welcome to SecureChat™  ***")
        try: # Check that server is running
            _ = requests.get(f"http://{SERVER_IP}/")
        except requests.exceptions.ConnectionError:
            # This is not fatal, but the user should be warned
            print("\nERROR: Could not connect to SecureChat™ server.\n")
        while self.ongoing:
            try:
                self.receive_message()
                self.display_UI()
                self.parse_command()
            except KeyboardInterrupt:
                self.ongoing = False
        # End of REPL, clean up
        if self.authenticated:
            print("Authenticated, logging out")
            self.logout(None)
    # --------------------------------------------------------------------------