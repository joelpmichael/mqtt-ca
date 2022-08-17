import logging
logger = logging.getLogger(__name__)

import json

conf = {}

def log_start(log_level, log_dest):
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % log_level)
    log_handler = None
    if log_dest == 'CONSOLE':
        log_handler = logging.StreamHandler()
    else:
        log_handler = logging.FileHandler(filename=log_dest[0])
        
    log_handler.set_name('cmdline')
        
    logging.basicConfig(format='%(asctime)s %(levelname)s:%(name)s:%(message)s', level=numeric_level, handlers=[log_handler])
    
    logger.info("Logging started. Level:{}, Output:{}".format(log_level, log_dest))

def log_config(log_conf):
    logger.info("Configuring logging")
    logger.debug("Logger configuration: {}".format(log_conf))
    root_logger = logging.getLogger()
    
    if 'output' in log_conf.keys():
        new_handler = None
        if log_conf['output'] == 'CONSOLE':
            if type(root_logger.handlers[0]) is logging.FileHandler:
                logger.info("Adding CONSOLE logger from configuration")
                new_handler = logging.StreamHandler()
        else:
            logger.info("Adding FILE:{} logger from configuration".format(log_conf['output']))
            new_handler = logging.FileHandler(filename=log_conf['output'])
            
            if type(root_logger.handlers[0]) is logging.FileHandler:
                if root_logger.handlers[0].baseFileName == new_handler.baseFilename:
                    logger.debug("FILE logger already exists from cmdline, skipping")
                    new_handler = None

        if new_handler != None:
            new_handler.set_name('config')
            new_handler.setFormatter(root_logger.handlers[0].formatter)
            root_logger.addHandler(new_handler)

    if 'level' in log_conf.keys():
        numeric_level = getattr(logging, log_conf['level'].upper(), None)
        if not isinstance(numeric_level, int):
            logger.error('Invalid log level {} in configuration'.format(log_conf['level']))
            logger.error('Valid log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL')
        else:
            current_level = root_logger.getEffectiveLevel()
            if current_level > numeric_level:
                logger.info("Setting log level to {}".format(log_conf['level']))
                root_logger.setLevel(numeric_level)
                
    logger.debug("Logging configuration complete")

    
    
def conf_load(file):
    logger.info("Reading config file {}".format(file))
    with open(file, "r") as cfgfile:
        conf = json.load(cfgfile)

    if "log" in conf.keys():
        log_config(conf["log"])

    print(conf)
