import mqtt_utils, time

clientBob = mqtt_utils.connect_mqtt("Bob_2022")
mqtt_utils.publish(clientBob, "BOBACB.in", "Hola Alice")
mqtt_utils.subscribe(clientBob, "ALICEACB.out")
clientBob.loop_start()
while True:
    time.sleep(100)
