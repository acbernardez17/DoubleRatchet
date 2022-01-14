"""
Authors: Antonio Cebreiro Bernardez y Gonzalo Abal
        Double Ratchet Implementation with MQTT Server
"""

import os
from user import User

# THIS CODE WAS USED TO TEST LOCALLY ###

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
    b_msg_1 = Bob.send("Hello world!")
    print(Alice.receive(b_msg_1))
    b_msg_2 = Bob.send("This is Bob's second message")
    print(Alice.receive(b_msg_2))
    a_msg_1 = Alice.send("Hello, I'm Alice!")
    print(Bob.receive(a_msg_1))
    b_msg_3 = Bob.send("Nice to meet you Alice!, I'm Bob")
    print(Alice.receive(b_msg_3))
