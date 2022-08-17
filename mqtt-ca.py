#!/usr/bin/env python3

import ssl
import time
import logging

import paho.mqtt.client as mqtt

from MQTT_CA import config, daemon, monitor, provision

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MQTT-CA application control')
    parser.add_argument('--config-file', default="config.json")
    parser.add_argument('--log-level', default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument('--log-dest', default="CONSOLE", nargs=1)

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
    config.log_start(args.log_level, args.log_dest)
    logger = logging.getLogger(__name__)
    config.conf_load(args.config_file)
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
