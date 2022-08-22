import logging
logger = logging.getLogger(__name__)

from MQTT_CA import config, mqconn
daemon_config = {}

import paho.mqtt.client as mqtt
mq = mqtt.Client()

import time # for time.sleep

def daemon_on_connect(client, userdata, flags, rc):
    logger.debug('Callback daemon_on_connect client={} userdata={} flags={} rc={}'.format(client, userdata, flags, rc))
    mq.publish('mqtt-ca/online', 1, qos=0, retain=True)

def daemon_on_disconnect(client, userdata, rc):
    logger.debug('Callback daemon_on_disconnect client={} userdata={} rc={}'.format(client, userdata, rc))

def daemon_on_message(client, userdata, message):
    logger.debug('Callback daemon_on_message client={} userdata={} message={}'.format(client, userdata, message))

def daemon_on_publish(client, userdata, mid):
    logger.debug('Callback daemon_on_publish client={} userdata={} mid={}'.format(client, userdata, mid))

def daemon_on_subscribe(client, userdata, mid, granted_qos):
    logger.debug('Callback daemon_on_subscribe client={} userdata={} mid={} granted_qos={}'.format(client, userdata, mid, granted_qos))

def daemon_on_unsubscribe(client, userdata, mid):
    logger.debug('Callback daemon_on_unsubscribe client={} userdata={} mid={}'.format(client, userdata, mid))

def daemon_sign_cert(client, userdata, message):
    logger.debug('Callback daemon_sign_cert client={} userdata={} message={}'.format(client, userdata, message))

def daemon_tick_timestamp():
    pass

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
    mqconn.connect(mq)
    while mq.is_connected() == False:
        logger.warning("Waiting 5s for MQTT connection")
        time.sleep(5)
        
    mq.will_set('mqtt-ca/online', 0, qos=0, retain=True)
    while True:
        (result, mid) = mq.subscribe('mqtt-ca/+/csr', qos=1)
        if result == mqtt.MQTT_ERR_SUCCESS:
            break
        logger.warning("Waiting 5s for MQTT subscribe")
        time.sleep(5)
    
    # step 3 - create background tick thread
    
    # step 4 - subscribe to CSR topics
