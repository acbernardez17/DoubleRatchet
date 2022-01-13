import os
from user import User
import mqtt_utils, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


def on_message(client, userdata, msg):
    if not first_flag:
        Alice.state.diffieHellman_remote = X25519PublicKey.from_public_bytes(msg.payload)
        msg = Alice.state.public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PublicFormat.Raw)
        mqtt_utils.publish(clientAlice, "ACB.out", msg)
        flag = True
        return 
        # Get Bob's public key
        # Send Alice's public key
    print(chr(27)+"[1;31m" + "\n\nBob:")
    print(msg.payload)
    print(Alice.receive(msg.payload))
    print(chr(27)+"[1;35m" + "\n\nAlice:")


if __name__ == "__main__":
    first_flag = False
    # Generating the first shared root key of 32 bytes
    initial_root_key = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 

    # Initializing users that are going to communicate
    Alice = User("Alice", initial_root_key)
    # Bob = User("Bob", initial_root_key)

    # Initialize ratchets
    # Alice.initialize_ratchet(Bob.state.public_key)
    # Bob.initialize_ratchet(Alice.state.public_key)
    
    clientAlice = mqtt_utils.connect_mqtt("ALICE")
    mqtt_utils.subscribe(clientAlice, "ACB.in")
    clientAlice.on_message = on_message
    clientAlice.loop_start()
    time.sleep(1)
    
    while True: 
        value = input(chr(27)+"[1;35m"+"\n\nAlice:")
        print(chr(27)+"[0;30m")
        msg = Alice.send(value)
        mqtt_utils.publish(clientAlice, "ACB.out", msg)
        



    # # Now both have the same root key and the shared secret
    # b_msg_1 = Bob.send("Hello world!")
    # print(Alice.receive(b_msg_1))
    # b_msg_2 = Bob.send("This is Bob's second message")
    # print(Alice.receive(b_msg_2))
    # a_msg_1 = Alice.send("Hello, I'm Alice!")
    # print(Bob.receive(a_msg_1))
    # b_msg_3 = Bob.send("Nice to meet you Alice!, I'm Bob")
    # print(Alice.receive(b_msg_3))
    # # TODO Instead of local communication use the MQTT Server
    # # TODO Implement the logic to send/receive messages
