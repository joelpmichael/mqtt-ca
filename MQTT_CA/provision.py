import logging
logger = logging.getLogger(__name__)

from MQTT_CA import mqtt

def run(args):
    logger.info("Starting PROVISION mode")
    logger.debug("PROVISION args:{}".format(args))
