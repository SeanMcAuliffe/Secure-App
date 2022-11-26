import zmq
import random


class RxSocket:
    """ Class for a thread that listens for incoming messages
    from other peers. The thread is responsible for receiving
    session establishment challenges from peers, and completing
    the session estalibhsment process. Once a session is established,
    the thread is responsible for receiving a chat message from the
    peer and placing it in the shared message buffer with the main
    thread. """
    def __init__(self, rx_buffer):
        """ Creates a new zmq REP socket and binds it to a 
        random port. """
        self.port = random.randint(49152, 65535)
        context = zmq.Context()
        self.rx_socket = context.socket(zmq.REP)
        self.rx_socket.bind(f"tcp://*:{self.port}")

    def start(self):
        while True:
            # Receive a message from the socket
            # If the message is a session establishment challenge
            #   accept the session
            # If the message is a chat message under a valid session
            #   add the message to the shared message buffer
            pass

    # --------------------------------------------------------------------------
    def accept_session(self, args):
        """ Handles the process of establishing a secure session when
        initated by a remote peer client. The establish_session() method
        in TerminalChat initiates the session handhshake process when a
        peer client sends a message. """
        # STEP ONE: COMPLETE CHALLENGE AND VERIFY SENDER NETWORK LOCATION
        # STEP TWO: GENERATE SESSION KEYPAIR
        # TODO: Implement this function
        pass
    # --------------------------------------------------------------------------