"""
Authors: Antonio Cebreiro Bernardez y Gonzalo Abal
        Double Ratchet Implementation with MQTT Server
"""

# pip3 install paho.mqtt
from paho.mqtt import client as mqtt_client

broker = "52.209.186.238"
port = 1883


def connect_mqtt(client_id):
    def on_connect(_, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
        else:
            print("Failed to connect, return code %d\n", rc)

    # Set Connecting Client ID
    client_mqtt = mqtt_client.Client(client_id)
    client_mqtt.on_connect = on_connect
    client_mqtt.connect(broker, port)
    return client_mqtt


def publish(client, topic, msg):
    client.publish(topic, msg)


def subscribe(client: mqtt_client, topic):
    def on_message(_, userdata, msg):
        print(msg.payload.decode())
    client.subscribe(topic)
    client.on_message = on_message
