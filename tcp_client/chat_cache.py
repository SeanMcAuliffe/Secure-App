class ChatCache:
    """A class for holding the history of a single chat in memory."""

    def __init__(self, id, recipient):
        self.id = id
        self.recipient = recipient
        self.latest_msg = 0
        self.message_history = {}