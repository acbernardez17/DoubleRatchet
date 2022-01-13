import os
from user import User


if __name__ == "__main__":
    # Generating the first shared root key of 32 bytes
    initial_root_key = os.urandom(32)

    # Initializing users that are going to communicate
    Alice = User("Alice", initial_root_key)
    Bob = User("Bob", initial_root_key)

    # Initialize ratchets
    Alice.initialize_ratchet(Bob.state.public_key)
    Bob.initialize_ratchet(Alice.state.public_key)

    # Now both have the same root key and the shared secret
    msg = Bob.send("Hello world!")
    print(Alice.receive(msg))
    print("HI")
    # TODO Instead of local communication use the MQTT Server
    # TODO Implement the logic to send/receive messages
