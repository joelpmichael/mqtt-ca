import logging

logger = logging.getLogger(__name__)

from MQTT_CA import config, mqconn

daemon_config = {}

import paho.mqtt.client as mqtt

mq = mqtt.Client(protocol=mqtt.MQTTv5)

import io
import threading
import time  # for time.sleep
from datetime import datetime as datetime
from datetime import timezone as timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def daemon_on_connect(client: mqtt.Client, userdata, flags, reasonCode, properties):
    logger.debug('Callback daemon_on_connect client={} userdata={} flags={} reasonCode={} properties={}'.format(client, userdata, flags, reasonCode, properties))

def daemon_on_disconnect(client: mqtt.Client, userdata, reasonCode, properties):
    logger.debug('Callback daemon_on_disconnect client={} userdata={} reasonCode={} properties={}'.format(client, userdata, reasonCode, properties))
    client.loop_stop()
    time.sleep(11)
    client.loop_start()
    
def daemon_on_message(client: mqtt.Client, userdata, message):
    logger.debug('Callback daemon_on_message client={} userdata={} message={}'.format(client, userdata, message))

def daemon_on_publish(client: mqtt.Client, userdata, mid):
    logger.debug('Callback daemon_on_publish client={} userdata={} mid={}'.format(client, userdata, mid))

def daemon_on_subscribe(client: mqtt.Client, userdata, mid, reasonCodes, properties):
    logger.debug('Callback daemon_on_subscribe client={} userdata={} mid={} reasonCodes={} properties={}'.format(client, userdata, mid, reasonCodes, properties))

def daemon_on_unsubscribe(client: mqtt.Client, userdata, mid, properties, reasonCodes):
    logger.debug('Callback daemon_on_unsubscribe client={} userdata={} properties={}, reasonCodes={}'.format(client, userdata, mid, properties, reasonCodes))

def daemon_sign_cert(client: mqtt.Client, userdata, message):
    logger.debug('Callback daemon_sign_cert client={} userdata={} message={}'.format(client, userdata, message))

def daemon_tick_timestamp():
    while True:
        while mq.is_connected() == False:
            logger.warning("Waiting 5s for MQTT connection")
            time.sleep(5)
        now_timestamp = datetime.now(timezone.utc)
        logger.debug("DAEMON Tick at {}".format(datetime.isoformat(now_timestamp)))
        mq.publish('mqtt-ca/timestamp-utc', datetime.isoformat(now_timestamp), qos=0, retain=True)
        mq.publish('mqtt-ca/online', 1, qos=0, retain=True)
        yield()
        now_timestamp = datetime.now(timezone.utc)
        # tick once per minute
        time.sleep(60.1-(now_timestamp.microsecond / 1000000)-(now_timestamp.second))

def run(args):
    logger.info("Starting DAEMON mode")
    logger.debug("DAEMON args: {}".format(args))

    global daemon_config
    daemon_config = config.get_config("daemon")
    logger.debug("DAEMON config: {}".format(daemon_config))

    global mq
    mq.enable_logger()
    
    # step 1 - configure MQTT callbacks
    mq.on_connect = daemon_on_connect
    mq.on_disconnect = daemon_on_disconnect
    mq.on_message = daemon_on_message
    mq.on_publish = daemon_on_publish
    mq.on_subscribe = daemon_on_subscribe
    mq.on_unsubscribe = daemon_on_unsubscribe
    
    mq.message_callback_add('mqtt-ca/+/csr', daemon_sign_cert)
    
    # step 2 - connect to MQTT
    mq.will_set('mqtt-ca/online', 0, qos=0, retain=True)
    mqconn.connect(mq)
    while mq.is_connected() == False:
        logger.warning("Waiting 5s for MQTT connection")
        time.sleep(5)
        
    # step 4 - subscribe to CSR topics
    while True:
        (result, mid) = mq.subscribe('mqtt-ca/+/csr', options=mqtt.SubscribeOptions(qos=1))
        if result == mqtt.MQTT_ERR_SUCCESS:
            break
        logger.warning("Waiting 5s for MQTT subscribe")
        time.sleep(5)

    
    # step 3 - create background tick thread
    logger.info("Starting ticker thread")
    tick_thread = threading.Thread(target=daemon_tick_timestamp, daemon=True)
    tick_thread.start()
    logger.debug("Ticker thread started")
    
    # main thread waits forever now, MQTT callbacks handle processing in separate thread
    while True:
        yield()
        time.sleep(60)
