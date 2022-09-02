import logging

logger = logging.getLogger(__name__)

from MQTT_CA import mqconn, renew, config

monitor_config = {}

import paho.mqtt.client as mqtt

mq = mqtt.Client(protocol=mqtt.MQTTv5)

import threading
import time  # for time.sleep
from datetime import datetime as datetime, timedelta
from datetime import timezone as timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ed448
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, BestAvailableEncryption, NoEncryption
from cryptography.x509.oid import NameOID

import io
import gc
import os

new_key = None
new_cert = None
csr_sent = False
cert_received = None

def renew_cert(client: mqtt.Client, userdata, message: mqtt.MQTTMessage):
    logger.debug('Callback renew_cert client={} userdata={} message={}'.format(client, userdata, message))
    global csr_sent
    if csr_sent == False:
        # spurious re-transmission (possibly retained message, but we didn't even want one of those)
        return

    global cert_received
    cert_received = x509.load_der_x509_certificate(message.payload)

def run(certfile: str, keyfile: str, mq: mqtt.Client):
    logger.info("Starting RENEW")
    logger.debug("RENEW cert:{} key:{} mq:{}".format(certfile, keyfile, mq))
    
    # load certificate
    cert = None
    with io.FileIO(certfile, "r") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.readall())
    
    if cert == None:
        logger.critical("Unable to load certificate")
        raise ValueError(cert)

    cert_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    logger.debug("Certificate CN:{}".format(cert_cn))

    mq.message_callback_add('mqtt-ca/{}/cert'.format(cert_cn), renew_cert)
    mq.subscribe('mqtt-ca/{}/cert'.format(cert_cn), options=mqtt.SubscribeOptions(qos=0, retainHandling=mqtt.SubscribeOptions.RETAIN_DO_NOT_SEND))

    # generate new key
    new_csr = x509.CertificateSigningRequestBuilder()
    new_csr = new_csr.subject_name(cert.subject)
    global new_key
    global new_cert
    csr_sign_algo = None

    monitor_config = config.get_config("monitor")
    mqtt_config = config.get_config("mqtt")
    mqtt_keyfile_password = None
    if "keyfile_password" in mqtt_config.keys():
        mqtt_keyfile_password = mqtt_config['keyfile_password']
        logger.info("Setting MQTT key file password")
        
    new_keyfile_encryption = NoEncryption()
    if mqtt_keyfile_password != None:
        new_keyfile_encryption = BestAvailableEncryption(mqtt_keyfile_password)

    if monitor_config['algorithm'] == 'rsa':
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=monitor_config['keylen'])
        csr_sign_algo = hashes.SHA256()
    elif monitor_config['algorithm'] == 'ed25519':
        new_key = ed25519.Ed25519PrivateKey.generate()
    elif monitor_config['algorithm'] == 'ed448':
        new_key = ed448.Ed448PrivateKey.generate()
    else:
        logger.critical('Unknown key type:{} - must be rsa, ed25519 or ed448'.format(monitor_config['algorithm']))
        raise ValueError(monitor_config['algorithm'])

    with io.FileIO("{}.new".format(keyfile), mode="w") as new_keyfile:
        logger.info("Writing new private key to file {}".format(new_keyfile.name))
        new_keyfile.write(new_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, new_keyfile_encryption))
        
    # fix permissions on new keyfile
    keyfile_stat = os.stat(keyfile)
    os.chown("{}.new".format(keyfile), uid=keyfile_stat.st_uid, gid=keyfile_stat.st_gid)
    os.chmod("{}.new".format(keyfile), mode=keyfile_stat.st_mode)
        
    new_csr = new_csr.sign(new_key, csr_sign_algo)

    csr_sent = True
    logger.info("Sending CSR to MQTT-CA")
    mq.publish('mqtt-ca/{}/csr'.format(cert_cn), new_csr.public_bytes(Encoding.DER), qos=1, retain=True)

    # the second half of this happens in the monitor_cert callback
    global cert_received
    cert_valid = False
    while cert_valid == False:
        while cert_received == None:
            logger.debug("Waiting for MQTT-CA to send signed certificate")
            time.sleep(10)
            
        # received signed cert
        # make sure cert matches the key
        if cert_received.public_key() != new_key.public_key():
            logger.error("MQTT-CA sent certificate from different key?")
            logger.debug("Received cert:{}".format(cert_received))
            cert_received = None
            continue
        
        cert_valid = True
        break

    del new_key
    gc.collect()

    with io.FileIO("{}.new".format(certfile), mode="w") as new_certfile:
        logger.info("Writing new certificate to file {}".format(new_certfile.name))
        new_certfile.write(cert_received.public_bytes(Encoding.PEM))
    
    # fix permissions on new certfile
    certfile_stat = os.stat(certfile)
    os.chown("{}.new".format(certfile), uid=certfile_stat.st_uid, gid=certfile_stat.st_gid)
    os.chmod("{}.new".format(certfile), mode=certfile_stat.st_mode)
    
    # move original cert and key out of the way
    os.rename(keyfile, "{}.prev".format(keyfile))
    os.rename("{}.new".format(keyfile),keyfile)
    os.rename(certfile, "{}.prev".format(certfile))
    os.rename("{}.new".format(certfile),certfile)
    
    # bump MQTT session to use new keys
    mq.disconnect()
    mqconn.connect(mq)

    cert_received = False
    csr_sent = False
