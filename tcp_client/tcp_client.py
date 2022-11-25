from chat import TerminalChat
import zmq # https://zeromq.org/languages/python/


# ------------------------------------------------------------------------------
def main():

    # Create ZMQ ports for sending and receiving data
    # from other peers
    context = zmq.Context()
    tx = context.socket(zmq.REQ)
    tx.connect("tcp://localhost:56122")
    rx = context.socket(zmq.REP)
    rx.bind("tcp://*:56122")

    chat_client = TerminalChat(tx, rx)
    chat_client.run()
    chat_client.save_messages()
# ------------------------------------------------------------------------------


if __name__ == "__main__":
    main()