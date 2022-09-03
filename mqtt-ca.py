#!/usr/bin/env python3

from argparse import ArgumentParser
import ssl
import time
import logging
import argparse


import paho.mqtt.client as mqtt

from MQTT_CA import config, daemon, monitor, provision

if __name__ == "__main__":
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
