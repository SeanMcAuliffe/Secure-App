from queue import LifoQueue

class MessageBuffer:
    """ Object shared between TerminalChat and RxPort threads. Provides a
    thread-safe queue for storing incoming messages to be later processed by
    the TerminalChat thread during it's next REPL loop. """
    def __init__(self):
        self.q = LifoQueue(10)

    def add_msg(self, msg):
        self.q.put(msg, block=True, timeout=1)

    def get_msg(self):
        return self.q.get(block=True, timeout=1)

    def is_empty(self):
        return self.q.empty()

