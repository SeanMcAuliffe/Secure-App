from chat import TerminalChat
from buffer import MessageBuffer
from rx import RxSocket
import zmq # https://zeromq.org/languages/python/


# ------------------------------------------------------------------------------
def main():

    # Create ZMQ socket for sending messages
    context = zmq.Context()
    tx = context.socket(zmq.REQ)
    tx.connect("tcp://localhost:56122")

    # Create message buffer for receiving messages
    rx_buffer = MessageBuffer()

    # Run the receiving thread
    rx = RxSocket(rx_buffer)
    rx_port = rx.port

    # Run the chat client
    chat_client = TerminalChat(tx, rx_buffer, rx_port)
    chat_client.run()
    rx.start()
# ------------------------------------------------------------------------------


if __name__ == "__main__":
    main()