import logging
logger = logging.getLogger(__name__)

from MQTT_CA import mqconn

def run(args):
    logger.info("Starting MONITOR mode")
    logger.debug("MONITOR args:{}".format(args))
