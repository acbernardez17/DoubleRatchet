from random import random
from user import User
import mqtt_utils
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


def on_message(client, userdata, msg):
    if Alice.state.diffieHellman_remote is None:
        Alice.state.diffieHellman_remote = X25519PublicKey.from_public_bytes(msg.payload)
        print(f"[+] RECEIVED KEY: {msg.payload}")
        send_initial_public_key_msg = Alice.state.public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                                          format=serialization.PublicFormat.Raw)
        mqtt_utils.publish(clientAlice, "ACB.out", send_initial_public_key_msg)
        return
    else:
        # print(chr(27) + "[1;31m" + "\n\nBob:")
        # print(msg.payload)
        print(f'[+] Bob says: {Alice.receive(msg.payload).decode("utf-8")}')
        print(chr(27) + "[1;35m" + "\nAlice:")


if __name__ == "__main__":
    first_flag = False
    # Generating the first shared root key of 32 bytes
    initial_root_key = b"My 32-character initial_root_key"

    # Initializing users that are going to communicate
    Alice = User("Alice", initial_root_key)

    # Connect with a suffix of a random string to avoid interferences
    clientAlice = mqtt_utils.connect_mqtt("ALICE" + str(random()))
    mqtt_utils.subscribe(clientAlice, "ACB.in")
    clientAlice.on_message = on_message
    clientAlice.loop_start()
    send_public_key_msg = Alice.state.public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                              format=serialization.PublicFormat.Raw)
    # mqtt_utils.publish(clientAlice, "ACB.out", send_public_key_msg)

    time.sleep(1)

    while True:
        try:
            value = input(chr(27) + "[1;35m" + "\nAlice:")
            print(chr(27) + "[0;30m")
            text_to_send = Alice.send(value)
            mqtt_utils.publish(clientAlice, "ACB.out", text_to_send)
        except KeyboardInterrupt:
            print("[+] Finishing conversation...")
            break

    # # Now both have the same root key and the shared secret
    # b_msg_1 = Bob.send("Hello world!")
    # print(Alice.receive(b_msg_1))
    # b_msg_2 = Bob.send("This is Bob's second message")
    # print(Alice.receive(b_msg_2))
    # a_msg_1 = Alice.send("Hello, I'm Alice!")
    # print(Bob.receive(a_msg_1))
    # b_msg_3 = Bob.send("Nice to meet you Alice!, I'm Bob")
    # print(Alice.receive(b_msg_3))
