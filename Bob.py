"""
Authors: Antonio Cebreiro Bernardez y Gonzalo Abal
        Double Ratchet Implementation with MQTT Server
"""

from random import random
from user import User
import mqtt_utils
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


def on_message(client, userdata, msg):
    if Bob.state.diffieHellman_remote is None:
        Bob.state.diffieHellman_remote = X25519PublicKey.from_public_bytes(msg.payload)
        return
    else:
        print(f'\n[+] Alice says: {Bob.receive(msg.payload).decode("utf-8")}')


if __name__ == "__main__":
    # Generating the first shared root key of 32 bytes
    initial_root_key = b"My 32-character initial_root_key"

    # Initializing users that are going to communicate
    Bob = User("Bob", initial_root_key)

    # Connect with a suffix of a random string to avoid interferences
    clientBob = mqtt_utils.connect_mqtt("BOB" + str(random()))
    mqtt_utils.subscribe(clientBob, "ACB.out")
    clientBob.on_message = on_message
    clientBob.loop_start()

    send_public_key_msg = Bob.state.public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                            format=serialization.PublicFormat.Raw)
    mqtt_utils.publish(clientBob, "ACB.in", send_public_key_msg)

    time.sleep(1)

    while True:
        try:
            value = input(chr(27) + "[1;35m" + "Bob:")
            text_to_send = Bob.send(value)
            mqtt_utils.publish(clientBob, "ACB.in", text_to_send)
        except KeyboardInterrupt:
            print("[+] Finishing conversation...")
            break
