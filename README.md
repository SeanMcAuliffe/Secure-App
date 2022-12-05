# SENG 360: Group 10
## Security Specification and Implementation
**Group Members**
- Sean McAuliffe, V00913346
- Josh Morgan V00919952
- Naoya Pimlott,
- Chris Wong, V00780634
# Secure Messaging App
The security specification design process can be seen in tickets labelled design. The DFD and design decisions will be documented in the project wiki. Below is a brief description of the system architecture, installation, and usage.

## Design Overview

**Demo Video**  
https://www.youtube.com/watch?v=2pSsXbRunho

**Architecture**  
There are two components of the chat system, clients and a server. The server is used to 
store the credentials of user accounts, and to allow clients to login. The client cannot decrypt its
local chat history, or send messages, without first authenticating to the server. The server also
provides a mechanism for clients to find each others network location (IP + port), for p2p communication.  

**End-to-End encryption with plausible deniability and forward secrecy**  
Clients are authenticated to each other via public key, which the server stores. After a mutual Nonce-challenge
to the network location of the peer (for mutual authentication, verifying that a network location really is controlled by the user), a Diffie-Hellman key exchange is used to generate a shared symmetric key. During every DH key exhcange, each client will generate a new asymmetric keypair used for the exchange. The derived session key will be valid for the exchange of only a single message; in one direction. Afterwards, if a clietn wishes to send another message or respond to a received message, a new authentication ritual and DH key exchange will take place.

This design ensures that clients are mutually authenticated to each other, and provides end to end encryption with forward secrecy. Plausible deniability is ensured via message signature. After the DH key exchange produces a shared symmetric key, this key is used to derive a signature. The message is signed with this signature, and validated at the recipient. In this way, the message authenticity can be confirmed to the recipient, and third parties cannot distinguish which of the two clients signed the message, since it was signed by a shared key.

**At-Rest Encryption**  
Message history and keys are stored locally on the client. Multiple users may login to a single client on a single machine, and so to avoid leaking private key or message information, these files are encrypted on the disk. They are only decrypted in memory after the user has authenticated to the server.

The public key file (.pub), is stored in plaintext on disk. The private key file (.pem) is encrypted using the users password. The symmetric key (used to encrypt message history) is encrypted under a users public key (requiring the private key, and hence the password, to decrypt). The message history is encrypted under the symmetric key on disk. So, the only information which is plaintext on disk is the public key. Information is only decrypted when needed; in memory.

All messages between clients are end-to-end encrypted, the server does not posses the means to decrypt these communications.

**Current limitation**: login information sent from the client to the server is not encrypted in this implementation. In the real world, we would use HTTPS instead of HTTP, to ensure that login information is not
sent as plaintext via the network.

## Installation
To run the chat app, clone this repo and navigate into the project directory,
`group10`.

**Install the project depedencies**
```
python3 -m pip install -r requirements.txt
```

**Run the server locally**
```
python3 -m flask --app ./server/app.py run
```

**Run the client in a new terminal instance**
```
python3 tcp_client/tcp_client.py
```

## TUI Usage
Once you start the client you will see the following interface. It displays
information about what user you are logged in as, and what chat you have open.

```
***  Welcome to SecureChat™  ***

User: None
Active Chat: None
>> 
```

**List of commands**
- new_account: Opens an interface to register a new user account
- login: Log in as an existing user
- logout: Logout and close the TUI
- delete_account: Deletes the currently logged in account
- delete_msg `<msg_id>`: Deletes the message identified by `<msg_id>` from the currently active chat
- delete_chat `<chat_Id>`: Deletes a chat identified by `<chat_id>`
- list: Prints a list of all available chats, and their corresponding ID
- new_chat `<recipient>`: Creates a new chat with the user specified by `<recipient>`
- open `<chat_id>`: Opens the chat specified by `<chat_id>`
- close: Closes the currently active chat
- send `<msg>`: Sends the `<msg>` to the currently active chat
- help: Prints this list of commands
- exit: Logout and close the TUI
