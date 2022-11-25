import requests
import os
import json
from cache import ChatCache
from session import Session


SERVER_IP = "127.0.0.1:5000"


class TerminalChat:
    """ TerminalChat serves as the main thread which presents
    a REPL for the user to interact with the terminal chat app,
    and it prints the UI in response to state changes. """

    # +++++++++++++++++++++++++++++
    def __init__(self):
        self.ongoing = True
        self.username = None
        self.password = None
        self.cookie = None
        self.authenticated = False # is user logged in?
        self.session = None # connection to peer client
        # Stores chat_id (int) of active chat within msg_history
        self.active_chat = None
        # Stores ChatCache Object for all chats
        self.msg_history = None
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
            "refresh": self.refresh_chat,
            "help": self.ui_help,
            "exit": self.exit_client
        }
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    @staticmethod
    def clear_screen() -> None:
        if os.name == 'nt':
            _ = os.system('cls')
        else:
            _ = os.system('clear')
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def http_request(self, method, endpoint, data=None):
        """ Wrapper to send an HTTP request to the server. """
        url = f"http://{SERVER_IP}/{endpoint}"
        if data is not None:
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
                r = requests.post(url, data=data, headers=headers)
            else:
                raise ValueError("Invalid HTTP method.")
        except requests.exceptions.ConnectionError:
            print("Could not connect to SecureChat™ server.")
            return None
        return r
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
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
        data = {"username": username, "password": password}
        r = self.http_request("POST", "register", data)
        if r is not None and r.status_code == 200:
            print("Account created successfully.")
        elif r is not None and r.status_code != 200:
            print("Account creation failed.")
            print(r.text)
        else:
            print("Server connection failed.")
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
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
        data = {"username": username, "password": password}
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
        elif r is not None and r.status_code != 200:
            print("Login failed.")
            self.authenticated = False
            self.cookie = None
            print(r.text)
        else:
            print("Server connection failed.")
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def logout(self, args):
        """ Sends a request to the server to log out the user.
        Triggers the client to save the message history to disk
        and exit. """
        self.clear_screen()
        print("*** Logout of SecureChat™ ***")
        r = self.http_request("GET", "logout")
        if r is not None and r.status_code == 200:
            print("Logout successful.")
            self.authenticated = False
            self.active_chat = None
            self.cookie = None
            self.save_messages()
            self.exit_client(None)
        elif r is not None and r.status_code != 200:
            print("Logout failed.")
            print(r.text)
        else:
            print("Server connection failed.")
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
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
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def delete_msg(self, args):
        try:
            msg_id = int(args[0])
        except (IndexError, ValueError):
            print("Invalid message ID.")
            return
        if self.active_chat is None:
            print("No chat is currently open.")
            return
        if not self.authenticated:
            print("You must be logged in to delete messages.")
            return
        rc = self.msg_history.delete_message(self.active_chat, msg_id)
        if rc:
            print("Message deleted successfully.")
        else:
            print("Message deletion failed.")
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def delete_chat(self, args):
        try:
            chat_id = int(args[0])
        except (IndexError, ValueError):
            print("Invalid chat ID.")
            return
        if not self.authenticated:
            print("You must be logged in to delete chats.")
            return
        rc = self.msg_history.delete_chat(chat_id)
        if rc:
            print("Chat deleted successfully.")
        else:
            print("Chat deletion failed.")
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def list_chats(self, args):
        print(self.msg_history.list())
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def create_chat(self, args):
        pass
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def open_chat(self, args):
        """ Attempts to open a chat with the provided ID,
        sets the active_chat field to the ID if successful. """
        try:
            chat_id = int(args[0])
        except (IndexError, ValueError):
            print("Invalid chat ID.")
            return
        if not self.msg_history.chat_exists(chat_id):
            print("Chat does not exist.")
            return
        self.active_chat = chat_id
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def close_chat(self, args):
        """ Sets the active chat to None, this prevents the chat
        from being displayed in the UI, and prevents the user from
        querying or modifying the chat. """
        self.active_chat = None
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def establish_session(self, args):
        pass
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def send_message(self, args):
        pass
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def load_messages(self):
        """ Loads message history from JSON non-volatile storage
        into memory and decrypts it. Message history is stored on
        disk by username, and is only retrievable after a user has
        authenticated with the server. """
        filename = self.username + ".json"
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                # TODO: Decrypt messages
                self.msg_history = ChatCache(json.load(f))
        else:
            self.msg_history = ChatCache()
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def save_messages(self):
        """ When user logs out, or client exits, encrypt and save
        message history changes that have accumulated to the disk. """
        filename = self.username + ".json"
        with open(filename, "w") as f:
            # TODO: Encrypt messages
            f.write(json.dumps(self.msg_history.history))
    # +++++++++++++++++++++++++++++

    def display_UI(self):
        """ Print the state of the TerminalChat to the user. """
        if self.authenticated:
            print(f"User: {self.username}")
        else:
            print("User: None")
        if self.session is not None:
            pass # TODO: print session info
        else:
            print("Session: None")
        if self.active_chat is not None:
            print(f"Active Chat: {self.active_chat.header()}")
            print(self.active_chat)
        else:
            print("\nActive Chat: None")

    # +++++++++++++++++++++++++++++
    def ui_help(self, args):
        print(self.commands.keys())
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def exit_client(self, args):
        self.ongoing = False
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def parse_command(self):
        """ Parses a command from the user and executes it. """
        command_string = input(">> ").split(' ')
        cmd = command_string[0]
        args = command_string[1:]
        return cmd, args
    # +++++++++++++++++++++++++++++

    # +++++++++++++++++++++++++++++
    def run(self):
        """ REPL for the TerminalChat UI. """
        print("***  Welcome to SecureChat™  ***")
        try: # Check that server is running
            _ = requests.get(f"http://{SERVER_IP}/")
        except requests.exceptions.ConnectionError:
            # This is not fatal, but the user should be warned
            print("\nERROR: Could not connect to SecureChat™ server.\n")
        while self.ongoing:
            self.display_UI()
            cmd, args = self.parse_command()
            if cmd in self.commands:
                self.commands[cmd](args)
            else:
                print("Invalid command.")
        # End of REPL, clean up
        if self.authenticated:
            self.logout(None)
    # +++++++++++++++++++++++++++++