import logging
logger = logging.getLogger(__name__)

from MQTT_CA import mqtt

def run(args):
    logger.info("Starting DAEMON mode")
    logger.debug("DAEMON args:{}".format(args))
