#!/usr/bin/env python3

import ssl
import time

import paho.mqtt.client as mqtt

from MQTT_CA import daemon, monitor, provision

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("/mqtt-ca/+/csr")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MQTT-CA application control')
    subparser = parser.add_subparsers()
    parser_daemon = subparser.add_parser('daemon')
    parser_daemon.set_defaults(func=daemon.run)
    
    parser_monitor = subparser.add_parser('monitor')
    parser_monitor.add_argument('certfile', nargs=1)
    parser_monitor.add_argument('keyfile', nargs=1)
    parser_monitor.set_defaults(func=monitor.run)
    
    parser_provision = subparser.add_parser('provision')
    parser_provision.add_argument('name', nargs=1)
    parser_provision.set_defaults(func=provision.run)

    args = parser.parse_args()
    args.func(args)
    exit()
    
    
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    client.tls_set(ca_certs='/ca/certs/root.crt', certfile='/ca/certs/mqtt-ca.crt', keyfile='/ca/private/mqtt-ca.key', cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS, ciphers=None)
    client.tls_insecure_set(False)

    client.connect("mosquitto", 8883, 60)

    # Blocking call that processes network traffic, dispatches callbacks and
    # handles reconnecting.
    # Other loop*() functions are available that give a threaded interface and a
    # manual interface.
    client.loop_forever()
