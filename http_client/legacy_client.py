import json
import requests
import random
from os import system, name


SERVER_IP = "127.0.0.1:5000"


class ChatCache:
    """A class for storing a local cache of a chat message history from
    the server. Will need to be bootstrapped upon client startup, by 
    refreshing message list, telling server the latest message number is -1. """
    def __init__(self, id, recipient):
        self.id = id
        self.recipient = recipient
        self.latest_msg = 0
        self.message_history = {}

    def refresh_latest_msg_num(self) -> int:
        """Get the latest message number."""
        if len(self.message_history.keys()) > 0:
            nums = list(self.message_history.keys())
            nums.sort()
            self.latest_msg = nums[-1]
        else:
            self.latest_msg = -1

    # Called as a result of refresh_chat()
    def add_msg_multiple(self, msg: dict) -> int:
        #TODO: Parse the incoming messages and add them to the cache.
        """Add a dictionary of messages retrieved from the
        server to the cache."""
        self.message_history[msg['id']] = msg["sender"] + ": " + msg["message"]
        self.refresh_latest_msg_num()
        return self.latest_msg

    # Called as a result of send_message()
    def add_msg_single(self, msg: str) -> int:
        """Add a single message sent by the client to the cache."""
        self.refresh_latest_msg_num()
        #TODO: Refresh messages after each send to determine the new
        # latest message number
        self.message_history[self.latest_msg + 1] = msg
        self.refresh_latest_msg_num()
        return self.latest_msg

    # Called as a result of delete_message()
    def delete_msg(self, msg_id: int) -> bool:
        """Delete a message from the cache."""
        if msg_id in self.message_history.keys():
            del self.message_history[msg_id]
            self.refresh_latest_msg_num()
            return True
        else:
            return False

    def header(self):
        """Print the header of the chat."""
        return f"ID: {self.id} Recipient: {self.recipient}"

    def __str__(self):
        """Return a string representation of the cache."""
        # output = ""
        # if len(self.message_history.keys()) > 0:
        #     for msg_num in list(self.message_history.keys()).sort():
        #         output += f"{msg_num}: {self.message_history[msg_num]}\n"
        # return output
        return str(self.message_history)


class TerminalChat:
    """Class for the SecureChat™ chat client UI."""
    def __init__(self):
        self.ongoing = True
        self.active_chat = None
        self.chat_list = {}
        self.authenticated = False
        self.username = None
        self.cookie = None
        #TODO don't store passsword locally for account deletion
        # Move password authentication to server
        self.password = None
        self.commands = {
            "create_account": self.create_account,
            "login": self.login,
            "logout": self.logout,
            "delete_account": self.delete_account,
            "delete_msg": self.delete_msg,
            "delete_chat": self.delete_chat,
            "list": self.list_chats,
            "create": self.create_chat,
            "open": self.open_chat,
            "close": self.close_chat,
            "send": self.send_message,
            "refresh": self.refresh_chat,
            "help": self.ui_help,
            "exit": self.exit_client
            }

    @staticmethod
    def clear_screen() -> None:
        if name == 'nt':
            _ = system('cls')
        else:
            _ = system('clear')

    def http_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Sends an HTTP request to the server and returns the response."""
        if self.cookie is None:
            headers={"Content-Type":"application/json"}
        else:
            headers={"Content-Type":"application/json", "Cookie": self.cookie}
        data = json.dumps(data, indent=4)
        try:
            if method == "GET":
                r = requests.get(f"http://{SERVER_IP}/{endpoint}", headers=headers)
            elif method == "POST":
                r = requests.post(f"http://{SERVER_IP}/{endpoint}",
                                  json=data, headers=headers)
            else:
                raise ValueError("Invalid HTTP method.")
        except requests.exceptions.ConnectionError:
            print("ERROR: Could not connect to SecureChat™ server.")
            return None
        return r

    # Endpoint: /register
    def create_account(self, *args: tuple) -> None:
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

    # Endpoint: /login
    def login(self, *args: tuple) -> None:
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
        elif r is not None and r.status_code != 200:
            print("Login failed.")
            self.authenticated = False
            self.cookie = None
            print(r.text)
        else:
            print("Server connection failed.")

    # Endpoint: /logout
    def logout(self, *args: tuple) -> None:
        """Sends a request to the server to log out the user."""
        self.clear_screen()
        print("*** Logout of SecureChat™ ***")
        r = self.http_request("GET", "logout")
        if r is not None and r.status_code == 200:
            print("Logout successful.")
            self.authenticated = False
            self.active_chat = None
            self.cookie = None
        elif r is not None and r.status_code != 200:
            print("Logout failed.")
            print(r.text)
        else:
            print("Server connection failed.")

    # Endpoint /delete_account
    def delete_account(self, *args: tuple) -> None:
        """Sends a request to the server to delete the account."""
        self.clear_screen()
        print("*** Delete Account ***")
        try:
            password = input("Password: ")
            if password != self.password:
                print("Incorrect password.")
                return
            print("Are you sure you wish to proceed? y/n")
            confirm = input("> ")
            if confirm == "n":
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

    # Endpoint: /delete_message
    def delete_msg(self, *args: tuple) -> None:
        """Deletes msg number <msg_id> from the currently
        active chat."""
        try:
            msg_id = int(args[0][0])
        except (IndexError, ValueError):
            print("Invalid message ID.")
            return
        if self.active_chat is None:
            print("No chat is currently open.")
            return
        if not self.authenticated:
            print("You must be logged in to delete messages.")
            return
        data = {"message_id": msg_id}
        r = self.http_request("POST", "delete_message", data)
        if r is not None and r.status_code == 200:
            print("Message deleted successfully.")
            self.active_chat.delete_msg(msg_id)
        elif r is not None and r.status_code != 200:
            print("Message deletion failed.")
            print(r.text)
        else:
            print("Server connection failed.")

    # Local command
    def delete_chat(self, *args) -> None:
        try:
            chat_id = int(args[0][0])
        except (IndexError, ValueError):
            print("Please specify a chat ID.")
            return
        if chat_id not in self.chat_list.keys():
            print("Invalid chat ID.")
            return
        self.active_chat = None
        del self.chat_list[chat_id]

    # Local command
    def list_chats(self, *args) -> None:
        """Lists all stored chats"""
        print("\n---- Chat List -----")
        for id in self.chat_list.keys():
            print(self.chat_list[id].header())
        print("--------------------")

    # Local command
    def open_chat(self, *args: tuple) -> None:
        try:
            chat_id = args[0][0]
        except IndexError:
            print("No chat ID provided.")
            return
        """Opens a stored chat"""
        if chat_id in self.chat_list.keys():
            self.active_chat = self.chat_list[chat_id]
        else:
            print("Chat not found.")

    # Local command
    def close_chat(self, *args: tuple) -> None:
        """Closes the active chat, returns user to list of all chats."""
        self.active_chat = None

    # Local command
    def create_chat(self, *args: tuple) -> None:
        try:
            recipient = str(args[0][0])
        except (IndexError, ValueError, TypeError):
            print("Please specify a valid recipient.")
            return
        """Maybe we need an endpoint to create a new chat
        or maybe the send_message endpoint does this implicitly."""
        print(f"Creating chat with {recipient}...")
        for chat_id in self.chat_list.keys():
            chat = self.chat_list[chat_id]
            if chat.recipient == recipient:
                print("Chat already exists.")
                self.active_chat = chat
                return
        new_chat_id = random.randint(0, 255)
        while new_chat_id in self.chat_list.keys():
            new_chat_id = random.randint(0, 255)
        new_chat = ChatCache(new_chat_id, recipient)
        self.chat_list[new_chat_id] = new_chat
        self.active_chat = self.chat_list[new_chat_id]

    # Endpoint: /send_message
    def send_message(self, *args: tuple) -> None:
        """Sends <msg> to server to be delievered to <recipient>,
        adds the <msg> to the local cache of the chat, or creates
        a new chat if none exists."""
        try:
            msg = ""
            words = [word for word in args[0]]
            for word in words:
                msg = msg + word + " "
        except (IndexError, ValueError):
            print("No valid message provided.")
            return
        if self.active_chat == None:
            print("No active chat.")
            return
        if not self.authenticated:
            print("You must be logged in to send messages.")
            return
        data = {"receiver_username": self.active_chat.recipient, "message": msg}
        r = self.http_request("POST", "send_message", data)
        if r is not None and r.status_code == 200:
            # TODO: Server should echo back the last message number after
            # receiving this new message, so that cache doesn't get out of sync
            print("Message sent successfully.")
            self.active_chat.add_msg_single(msg)
        elif r is not None and r.status_code != 200:
            print("Message failed to send.")
            print(r.text)
        else:
            print("Serer connection failed.")

    # Endpoint: /retrieve_new_message
    def refresh_chat(self, *args) -> None:
        """Send a request to the server to retrieve all messages since
        <recent_msg_num> for the active chat. This function will also be
        used to bootstrap the cache from the server when the client first
        opens a chat, by sending latest_msg_num = -1."""
        print("First")
        data = {"latest_message_id": -1,
                "sender_username": self.active_chat.recipient}
        r = self.http_request("POST", "retrieve_new_message", data)
        if r is not None and r.status_code == 200:
            messages = r.json()
            for msg in messages:
                self.active_chat.add_msg_multiple(msg)
        print("Second")
        data = {"latest_message_id": -1,
                "sender_username": self.username}
        r = self.http_request("POST", "retrieve_new_message", data)
        if r is not None and r.status_code == 200:
            messages = r.json()
            for msg in messages:
                self.active_chat.add_msg_multiple(msg)
        elif r is not None and r.status_code == 404:
            print("No new messages.")
        elif r is not None and r.status_code != 200:
            print("Failed to refresh chat.")
            print(r.text)
        else:
            print("Server connection failed.")

    # Local command
    def ui_help(self, *args) -> None:
        """Prints the list of commands to the user."""
        print("*** Available commands: *** ")
        print("create_account\nlogin\nlogout\ndelete_account \
            \ndelete_msg <msg_id>\nlist - lists all stored chats \
            \ndelete_chat <chat_id> \
            \nopen <chat_id>\nclose - closes the currently active chat \
            \ncreate <recipient> - creates a new chat with <recipient> \
            \nsend <msg> - sends to currently active chat \
            \nrefresh - refreshes the currently active chat \
            \nhelp - prints this message\nexit")

    # Local command
    def exit_client(self, *args) -> None:
        """Encrypt any data to be stored to disk, exit the program."""
        self.ongoing = False
        pass

    def parse_command(self):
        input_str = input('> ')
        input_str = input_str.split(' ')
        cmd = input_str[0]
        args = None
        if len(input_str) > 1:
            args = input_str[1:]
        return cmd, args

    def run(self):
        print("***  Welcome to SecureChat™  ***")
        try: # Check that server is running
            _ = requests.get(f"http://{SERVER_IP}/")
        except requests.exceptions.ConnectionError:
            print("\nERROR: Could not connect to SecureChat™ server.\n")

        while self.ongoing: # Run main event loop
            #self.clear_screen()
            if self.authenticated:
                print(f"Logged in as {self.username}")
            else:
                print("Not logged in.")
            if self.active_chat is not None:
                print(f"Active Chat: {self.active_chat.header()}")
                print(self.active_chat)
            else:
                print("\nActive Chat: None")
            cmd, args = self.parse_command()
            if cmd in self.commands.keys():
                self.commands[cmd](args)
            else:
                print("Invalid command. Type 'help' for a list of commands.")
        # End of main event loop, clean up and exit
        self.logout()


def main():
    client = TerminalChat()
    client.run()



if __name__ == "__main__":
    main()
