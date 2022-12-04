class ChatCache:
    """ Wrapper class for storing message history in memory,
    provides methods for queirying and modifying the message history. 
    The history is stored as a list of dictionaries, each dictionary
    represents a chat. This history can easily be converted to a JSON
    string for encryption and local storage. """

    def __init__(self, history: dict = None):
        """ Unpack the loaded history if it exists, otherwise, otherwise
        initialize a new history. """
        self.history = history
        if history is not None:
            self.ids = [chat["chat_id"] for chat in self.history]
            self.users = [chat["username"] for chat in self.history]
        else:
            self.ids = []
            self.users = []
            self.history = []

    def refresh_list(self):
        """ Refresh the history data after a change has occured. """
        self.ids = [chat["chat_id"] for chat in self.history]
        self.users = [chat["username"] for chat in self.history]

    def list(self):
        """ Prints a list of the stored chats to the user"""
        out = "---- Chat List ----\n"
        for chat in self.history:
            out += str(chat["chat_id"]) + ": " + chat["username"] + "\n"
        return out + "-------------------"

    def chat_exists(self, chat_id):
        """ Determines if a chat exists, identified by an intenger. """
        return chat_id in self.ids

    def get_chat_by_id(self, chat_id):
        """ Return a chat object by its integer ID. """
        chat = None
        for c in self.history:
            if c["chat_id"] == chat_id:
                chat = c
                break
        return chat

    def get_chat_by_username(self, username):
        """ Return a chat object by its username field. """
        chat = None
        for c in self.history:
            if c["username"] == username:
                chat = c
                break
        return chat

    def active_user(self, chat_id):
        """ Return the username of the active chat, as identified
        by its integer ID."""
        chat = self.get_chat_by_id(chat_id)
        if chat is None:
            return None
        return chat["username"]

    def header_by_id(self, chat_id):
        """ Return a string representation of a chat, identified by
        its integer ID. """
        chat = self.get_chat_by_id(chat_id)
        if chat is None:
            return None
        return f"({chat_id}) {chat['username']}"

    def new_chat(self, recipient):
        """ Create a new chat object with a given recipient username, and
        add the chat to the history."""
        if self.get_chat_by_username(recipient) is not None:
            return False # chat already exists
        new_chat = {"chat_id": len(self.ids),
                    "username": recipient,
                    "history": []}
        self.history.append(new_chat)
        self.ids.append(new_chat["chat_id"])
        self.users.append(new_chat["username"])
        self.refresh_list()
        return True

    def add_message_by_id(self, chat_id, sender, message):
        """ Add a <message: str>, <sender: str> to a locally stored chat,
        as identified by its integer ID. """
        chat = self.get_chat_by_id(chat_id)
        if chat is None:
            return False
        msg_id = len(chat["history"])
        chat["history"].append({"msg_id": msg_id,
                                "sender": sender,
                                "message": message})
        return True

    def add_message_by_username(self, username, message):
        """ Add a <message: str>, <sender: str> to a locally stored chat,
        as identified by its username. """
        chat = self.get_chat_by_username(username)
        if chat is None:
            self.new_chat(username)
            chat = self.get_chat_by_username(username)
        msg_id = len(chat["history"])
        chat["history"].append({"msg_id": msg_id,
                                "sender": username,
                                "message": message})
        return True

    def delete_chat(self, chat_id):
        """ Removes a chat from the history, as identified by its integer
        ID. """
        chat = self.get_chat_by_id(chat_id)
        if chat is None:
            return False
        self.history.remove(chat)
        self.refresh_list()
        return True

    def delete_message(self, chat_id, msg_id):
        """ Deletes a single message, identified by its Message ID,
        from the chat identified by its integer ID. """
        chat = self.get_chat_by_id(chat_id)
        if chat is None:
            return False
        for msg in chat["history"]:
            if msg["msg_id"] == msg_id:
                chat["history"].remove(msg)
                return True
        return False

    def display_chat(self, chat_id):
        """ Prints out the entire chat history of a chat, identified by 
        its integer ID. """
        output_chat = self.get_chat_by_id(chat_id)
        if output_chat == None:
            return "Chat does not exist."
        out = f"---- Chat History with {output_chat['username']} ----\n"
        for msg in output_chat['history']:
            out += str(msg["msg_id"]) + " " + msg["sender"] + \
                      ": " + msg["message"] + "\n"
        return out + "---------------------------------"