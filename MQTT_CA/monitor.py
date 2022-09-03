import logging

logger = logging.getLogger(__name__)

from MQTT_CA import config, mqconn, renew

monitor_config = {}

import paho.mqtt.client as mqtt

mq = mqtt.Client(protocol=mqtt.MQTTv5)

import time  # for time.sleep
from datetime import datetime as datetime
from datetime import timedelta
from datetime import timezone as timezone


def monitor_on_connect(client: mqtt.Client, userdata, flags, reasonCode, properties):
    logger.debug('Callback monitor_on_connect client={} userdata={} flags={} reasonCode={} properties={}'.format(client,userdata, flags, reasonCode, properties))

def monitor_on_disconnect(client: mqtt.Client, userdata, reasonCode, properties):
    logger.debug('Callback monitor_on_disconnect client={} userdata={} reasonCode={} properties={}'.format(client,userdata, reasonCode, properties))
    client.loop_stop()
    time.sleep(30)
    client.loop_start()

def monitor_on_message(client: mqtt.Client, userdata, message):
    logger.debug('Callback monitor_on_message client={} userdata={} message={}'.format(client,userdata, message))

def monitor_on_publish(client: mqtt.Client, userdata, mid):
    logger.debug('Callback monitor_on_publish client={} userdata={} mid={}'.format(client,userdata, mid))

def monitor_on_subscribe(client: mqtt.Client, userdata, mid, reasonCodes, properties):
    logger.debug('Callback monitor_on_subscribe client={} userdata={} mid={} reasonCodes={} properties={}'.format(client,userdata, mid, reasonCodes, properties))

def monitor_on_unsubscribe(client: mqtt.Client, userdata, mid, properties, reasonCodes):
    logger.debug('Callback monitor_on_unsubscribe client={} userdata={} properties={}, reasonCodes={}'.format(client,userdata, mid, properties, reasonCodes))

ca_online = False
def monitor_ca_online(client: mqtt.Client, userdata, message: mqtt.MQTTMessage):
    logger.debug('Callback monitor_ca_online client={} userdata={} message={}'.format(client,userdata, message))
    global ca_online
    if message.payload == 0:
        ca_online = False
    elif message.payload == 1:
        ca_online = True
        client.subscribe('mqtt-ca/timestamp-utc')

ca_timestamp = datetime.now(timezone.utc)
def monitor_timestamp_utc(client: mqtt.Client, userdata, message: mqtt.MQTTMessage):
    logger.debug('Callback monitor_timestamp_utc client={} userdata={} message={}'.format(client,userdata, message))
    global ca_timestamp
    ca_timestamp = datetime.fromisoformat(message.payload.decode())
    logger.debug('MQTT-CA timestamp received: {}'.format(ca_timestamp.isoformat()))
    # timestamp is one-shot
    client.unsubscribe('mqtt-ca/timestamp-utc')
    
def run(args):
    logger.info("Starting MONITOR mode in background")
    logger.debug("MONITOR args:{}".format(args))
    
    import os
    pid = os.fork()
    if pid > 0:
        logger.debug("MONITOR parent process exit")
        exit(0)
    else:
        logger.debug("MONITOR child pid continuing")

    # override cert and key file
    config.conf['mqtt']['certfile'] = args.certfile[0]
    config.conf['mqtt']['keyfile'] = args.keyfile[0]
    
    global monitor_config
    monitor_config = config.get_config("monitor")
    logger.debug("MONITOR config: {}".format(monitor_config))

    global mq
    mq.enable_logger()
    
    # step 1 - configure MQTT callbacks
    mq.on_connect = monitor_on_connect
    mq.on_disconnect = monitor_on_disconnect
    mq.on_message = monitor_on_message
    mq.on_publish = monitor_on_publish
    mq.on_subscribe = monitor_on_subscribe
    mq.on_unsubscribe = monitor_on_unsubscribe
    
    mq.message_callback_add('mqtt-ca/timestamp-utc', monitor_timestamp_utc)
    mq.message_callback_add('mqtt-ca/online', monitor_ca_online)
    
    
    # main logic loop
    global ca_online
    global ca_timestamp
    while True:
        mqconn.connect(mq)
        while mq.is_connected() == False:
            logger.warning("Waiting 5s for MQTT connection")
            time.sleep(5)
        
        mq.subscribe('mqtt-ca/online', options=mqtt.SubscribeOptions(qos=0))
        mq.subscribe('mqtt-ca/timestamp-utc', options=mqtt.SubscribeOptions(qos=0))
        
        # sleep 1m15s to make sure that a new tick is received
        time.sleep(75)
        mq.subscribe('mqtt-ca/timestamp-utc', options=mqtt.SubscribeOptions(qos=0))
        
        if ca_online == False:
            logger.warning("MQTT-CA appears to be offline")
        
        # check clock skew from CA
        now_timestamp = datetime.now(timezone.utc)
        logger.debug('now_timestamp: {}'.format(now_timestamp.isoformat()))
        logger.debug('ca_timestamp: {}'.format(ca_timestamp.isoformat()))
        logger.debug('Timedelta: {}'.format(ca_timestamp - now_timestamp))
        if (ca_timestamp - now_timestamp) > timedelta(
            hours=monitor_config['skew_warn']['hours'],
            minutes=monitor_config['skew_warn']['minutes'],
        ) or (now_timestamp - ca_timestamp) > timedelta(
            hours=monitor_config['skew_warn']['hours'],
            minutes=monitor_config['skew_warn']['minutes'],
        ):
            logger.error("Time skew detected - local:{} remote:{} skew:{}".format(
                datetime.isoformat(now_timestamp), 
                datetime.isoformat(ca_timestamp),
                now_timestamp - ca_timestamp,
            ))
        
        # refresh cert
        renew.run(config.conf['mqtt']['certfile'], config.conf['mqtt']['keyfile'], mq)
