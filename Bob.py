import os
from user import User
import mqtt_utils, time

def on_message(client, userdata, msg):
    if not flag:
        print()
        # Get Bob's public key
        # Send Alice's public key
    print(chr(27)+"[1;31m" + "\n\nAlice:")
    print(msg.payload)
    print(Bob.receive(msg.payload))
    print(chr(27)+"[1;35m" + "\n\nBob:")

if __name__ == "__main__":
    flag = False
    # Generating the first shared root key of 32 bytes
    initial_root_key = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 

    # Initializing users that are going to communicate
    Alice = User("Alice", initial_root_key)
    Bob = User("Bob", initial_root_key)

    # Initialize ratchets
    Alice.initialize_ratchet(Bob.state.public_key)
    Bob.initialize_ratchet(Alice.state.public_key)


    clientBob = mqtt_utils.connect_mqtt("BOB")
    mqtt_utils.subscribe(clientBob, "ACB.out")
    clientBob.on_message = on_message
    clientBob.loop_start()
    time.sleep(1)

    while True:
        value = input(chr(27)+"[1;35m"+"\n\nBob:")
        print(chr(27)+"[1;30m")
        msg = Bob.send(value)
        mqtt_utils.publish(clientBob, "ACB.in", msg)




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
