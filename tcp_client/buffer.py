class IncomingMessageBuffer:
    """ Object shared between TerminalChat and RxPort threads. Provides a
    thread-safe queue for storing incoming messages to be later processed by
    the TerminalChat thread during it's next REPL loop. """
    def __init__(self):
        pass