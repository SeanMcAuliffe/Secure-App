from chat import TerminalChat
from buffer import MessageBuffer
from rx import RxSocket
import zmq # https://zeromq.org/languages/python/


# ------------------------------------------------------------------------------
def main():

    # Create ZMQ socket for sending messages
    context = zmq.Context()
    tx = context.socket(zmq.REQ)

    # Create message buffer for receiving messages
    rx_buffer = MessageBuffer()

    # Run the receiving thread
    rx_socket = RxSocket(rx_buffer)
    host_ip = "127.0.0.1" # TODO: Determine host IP

    # Run the chat client
    chat_client = TerminalChat(tx, rx_buffer, rx_socket, host_ip)
    chat_client.run()
# ------------------------------------------------------------------------------


if __name__ == "__main__":
    main()