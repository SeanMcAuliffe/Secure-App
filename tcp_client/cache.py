class ChatCache:
    """ Wrapper class for storing message history in memory,
    provides methods for queirying and modifying the message history. """
    def __init__(self, history: dict = None):
        # msg_history is loaded from JSON file
        self.history = history
        if history is not None:
            self.ids = [chat["id"] for chat in self.history]
            self.users = [chat["username"] for chat in self.history]
        else:
            self.ids = []
            self.users = []
            self.history = []

    def refresh_list(self):
        self.ids = [chat["id"] for chat in self.history]
        self.users = [chat["username"] for chat in self.history]

    def list(self):
        out = "---- Chat List ----\n"
        for chat in self.history:
            out += chat["chat_id"] + ": " + chat["username"] + "\n"
        return out + "--------------------\n"

    def get_chat_by_id(self, chat_id):
        chat = None
        for c in self.history:
            if c["chat_id"] == chat_id:
                chat = c
                break
        return chat

    def get_chat_by_username(self, username):
        chat = None
        for c in self.history:
            if c["username"] == username:
                chat = c
                break
        return chat

    def new_chat(self, recipient):
        if self.get_chat_by_username(recipient) is not None:
            return False # chat already exists

        new_chat = {"chat_id": len(self.ids), "username": recipient, "history": []}
        self.history.append(new_chat)
        self.ids.append(new_chat["chat_id"])
        self.users.append(new_chat["username"])
        self.refresh_list()
        return True

    def delete_chat(self, chat_id):
        chat = self.get_chat_by_id(chat_id)
        if chat is None:
            return False
        self.history.remove(chat)
        self.refresh_list()
        return True

    def delete_message(self, chat_id, msg_id):
        chat = self.get_chat_by_id(chat_id)
        if chat is None:
            return False
        for msg in chat["history"]:
            if msg["msg_id"] == msg_id:
                chat["history"].remove(msg)
                return True
        return False

    def display_chat(self, chat_id):
        output_chat = self.get_chat_by_id(chat_id)
        if output_chat == None:
            return "Chat does not exist."
        out = f"---- Chat History with {output_chat['username']} ----\n"
        for msg in output_chat['history']:
            out += msg["sender"] + ": " + msg["message"] + "\n"
        return out + "----------------------\n"