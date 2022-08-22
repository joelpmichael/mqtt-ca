from distutils.command.clean import clean
import logging
logger = logging.getLogger(__name__)

from MQTT_CA import config, mqconn
mqtt_config = {}

import paho.mqtt.client as mqtt

def connect(mq: mqtt.Client):
    logger.info("Starting MQTT connection")

    global mqtt_config
    mqtt_config = config.get_config("mqtt")
    logger.debug("MQTT config: {}".format(mqtt_config))

    mqtt_host = None
    if "hostname" not in mqtt_config.keys():
        logger.warning("MQTT Host Name not configured, defaulting to 'mosquitto'")
        mqtt_host = 'mosquitto'
    else:
        mqtt_host = mqtt_config['hostname']
        logger.info("Setting MQTT hostname to {}".format(mqtt_host))


    mqtt_port = None
    if "port" not in mqtt_config.keys():
        logger.warning("MQTT Host Port not configured, defaulting to 1883")
        mqtt_port = 1883
    else:
        mqtt_port = mqtt_config['port']
        logger.info("Setting MQTT port to {}".format(mqtt_port))

        
    mqtt_keepalive = 60
    if "keepalive" in mqtt_config.keys():
        mqtt_keepalive = mqtt_config['keepalive']
        logger.info("Setting MQTT keepalive to {}".format(mqtt_keepalive))

    mqtt_reconnect_maxdelay = 60
    if "reconnect_maxdelay" in mqtt_config.keys():
        mqtt_reconnect_maxdelay = mqtt_config['reconnect_maxdelay']
        logger.info("Setting MQTT reconnect maxdelay to {}".format(mqtt_reconnect_maxdelay))
    # set reconnect max delay
    mq.reconnect_delay_set(min_delay=1, max_delay=mqtt_reconnect_maxdelay)
    
    if "username" in mqtt_config.keys() and "password" in mqtt_config.keys():
        if mqtt_config['username'] != None:
            logger.info("Setting MQTT username to {}".format(mqtt_config['username']))
            if mqtt_config['password'] != None:
                logger.info("Using configured MQTT password")
            # set username/password
            mq.username_pw_set(username=mqtt_config['username'], password=mqtt_config['password'])

    mqtt_tls_mode = False
    
    mqtt_insecure = True
    if "insecure" in mqtt_config.keys():
        mqtt_insecure = mqtt_config['insecure']
        logger.info("Setting MQTT insecure mode to {}".format(mqtt_insecure))
    mqtt_certfile = None
    if "certfile" in mqtt_config.keys():
        mqtt_certfile = mqtt_config['certfile']
        logger.info("Setting MQTT certificate file to {}".format(mqtt_certfile))
    mqtt_keyfile = None
    if "keyfile" in mqtt_config.keys():
        mqtt_keyfile = mqtt_config['keyfile']
        logger.info("Setting MQTT key file to {}".format(mqtt_keyfile))
    mqtt_cacert = None
    if "cacert" in mqtt_config.keys():
        mqtt_cacert = mqtt_config['cacert']
        logger.info("Setting MQTT CA certificate file to {}".format(mqtt_cacert))

    if mqtt_insecure == False or mqtt_port == 8883 or mqtt_certfile != None or mqtt_keyfile != None or mqtt_cacert != None:
        logger.info("Enabling MQTT TLS mode")
        mqtt_tls_mode = True
    else:
        logger.info("Disabling MQTT TLS mode")
        
    if mqtt_tls_mode == True:
        mq.tls_set(ca_certs=mqtt_cacert, certfile=mqtt_certfile, keyfile=mqtt_keyfile)
        mq.tls_insecure_set(mqtt_insecure)
        
    mq.connect_async(host=mqtt_host, port=mqtt_port, keepalive=mqtt_keepalive, clean_start=False)
    mq.loop_start()
