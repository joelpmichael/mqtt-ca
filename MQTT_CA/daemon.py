from hashlib import sha256
import logging

logger = logging.getLogger(__name__)

from MQTT_CA import config, mqconn, renew

daemon_config = {}

import paho.mqtt.client as mqtt

mq = mqtt.Client(protocol=mqtt.MQTTv5)

import io
import gc
import threading
import time  # for time.sleep
from datetime import datetime as datetime
from datetime import timezone as timezone
from datetime import timedelta as timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import ipaddress

ca_cert = x509.Certificate

def daemon_on_connect(client: mqtt.Client, userdata, flags, reasonCode, properties):
    logger.debug('Callback daemon_on_connect client={} userdata={} flags={} reasonCode={} properties={}'.format(client, userdata, flags, reasonCode, properties))

def daemon_on_disconnect(client: mqtt.Client, userdata, reasonCode, properties):
    logger.debug('Callback daemon_on_disconnect client={} userdata={} reasonCode={} properties={}'.format(client, userdata, reasonCode, properties))
    client.loop_stop()
    time.sleep(11)
    client.loop_start()
    
def daemon_on_message(client: mqtt.Client, userdata, message: mqtt.MQTTMessage):
    logger.debug('Callback daemon_on_message client={} userdata={} message={}'.format(client, userdata, message))

def daemon_on_publish(client: mqtt.Client, userdata, mid):
    logger.debug('Callback daemon_on_publish client={} userdata={} mid={}'.format(client, userdata, mid))

def daemon_on_subscribe(client: mqtt.Client, userdata, mid, reasonCodes, properties):
    logger.debug('Callback daemon_on_subscribe client={} userdata={} mid={} reasonCodes={} properties={}'.format(client, userdata, mid, reasonCodes, properties))

def daemon_on_unsubscribe(client: mqtt.Client, userdata, mid, properties, reasonCodes):
    logger.debug('Callback daemon_on_unsubscribe client={} userdata={} properties={}, reasonCodes={}'.format(client, userdata, mid, properties, reasonCodes))

def daemon_sign_cert(client: mqtt.Client, userdata, message: mqtt.MQTTMessage):
    logger.debug('Callback daemon_sign_cert client={} userdata={} message={}'.format(client, userdata, message))
    csr = x509.load_der_x509_csr(message.payload)
    logger.debug(csr.public_bytes(Encoding.PEM).decode())
    if csr.is_signature_valid == False:
        logger.error("Invalid signature on CSR")
        return

    csr_cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    logger.info("CSR for {} received, processing...".format(csr_cn))

    cert = x509.CertificateBuilder()
    cert = cert.subject_name(csr.subject)
    cert = cert.public_key(csr.public_key())
    cert = cert.issuer_name(ca_cert.subject)
    cert = cert.not_valid_before(datetime.today() - timedelta(days=1))
    cert = cert.not_valid_after(datetime.today() + timedelta(days = daemon_config['expiry']['days']))
    cert = cert.serial_number(x509.random_serial_number())

    cert = cert.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    cert = cert.add_extension(
        x509.KeyUsage(
            digital_signature=True, 
            content_commitment=True, 
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=False,
    )
    cert = cert.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
    )
    cert = cert.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False
    )
    
    if csr_cn == 'mosquitto':
        cert = cert.add_extension(
            x509.ExtendedKeyUsage(usages=[ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        add_san = []
        if 'mosquitto_subjectAltName' in daemon_config.keys():
            for san in daemon_config['mosquitto_subjectAltName']:
                if san[:4] == 'DNS:':
                    add_san.append(x509.DNSName(san[4:]))
                elif san[:3] == 'IP:':
                    add_san.append(x509.IPAddress(ipaddress.ip_address(san[3:])))
        if len(add_san) > 0:
            cert = cert.add_extension(
                x509.SubjectAlternativeName(add_san), critical=False
            )
    else:
        cert = cert.add_extension(
            x509.ExtendedKeyUsage(usages=[ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        
    sign_key = None
    with io.FileIO(daemon_config['signkey'], mode="r") as ca_keyfile:
        logger.info("Loading CA signing key")
        sign_password = None
        if daemon_config['signkey_password'] != None:
            sign_password = daemon_config['signkey_password'].encode()
        sign_key = serialization.load_pem_private_key(ca_keyfile.readall(), password=sign_password)
        del sign_password
        gc.collect()
    if sign_key == None:
        logger.critical("Unable to load CA private key")
        exit(1)

    sign_algo = None
    if isinstance(sign_key, rsa.RSAPrivateKey):
        sign_algo = hashes.SHA256()
        
    signed_cert = cert.sign(sign_key, sign_algo)
    logger.info("Certificate signed, sending...")
    logger.debug(signed_cert.public_bytes(Encoding.PEM).decode())
    mq.publish('mqtt-ca/{}/cert'.format(csr_cn), signed_cert.public_bytes(Encoding.DER), qos=1, retain=True)
    logger.debug("Certificate sent")


def daemon_ticker():
    global mq
    while True:
        while mq.is_connected() == False:
            logger.warning("Waiting 5s for MQTT connection")
            time.sleep(5)

        now_timestamp = datetime.now(timezone.utc)
        logger.debug("DAEMON Tick at {}".format(datetime.isoformat(now_timestamp)))
        mq.publish('mqtt-ca/timestamp-utc', datetime.isoformat(now_timestamp), qos=0, retain=True)
        mq.publish('mqtt-ca/online', 1, qos=0, retain=True)
        now_timestamp = datetime.now(timezone.utc)
        # tick once per minute
        time.sleep(60.1-(now_timestamp.microsecond / 1000000)-(now_timestamp.second))

def daemon_monitor():
    global mq
    mqtt_config = config.get_config('mqtt')
    while True:
        while mq.is_connected() == False:
            logger.warning("Waiting 5s for MQTT connection")
            time.sleep(5)

        renew.run(mqtt_config['certfile'], mqtt_config['keyfile'], mq)
        
def run(args):
    logger.info("Starting DAEMON mode")
    logger.debug("DAEMON args: {}".format(args))

    global daemon_config
    daemon_config = config.get_config("daemon")
    logger.debug("DAEMON config: {}".format(daemon_config))

    global mq
    mq.enable_logger()
    
    global ca_cert
    ca_cert = None
    with io.FileIO(daemon_config['signcert'], mode="r") as ca_certfile:
        logger.info("Loading CA signing certificate")
        ca_cert = x509.load_pem_x509_certificate(ca_certfile.readall())
    if ca_cert == None:
        logger.critical("Unable to load CA Certificate")
        exit(1)

    ca_cert_expiry = ca_cert.not_valid_after.replace(tzinfo=timezone.utc)
    logger.debug("CA Certificate expiry:{}".format(ca_cert_expiry.isoformat()))
    if ca_cert_expiry < datetime.now(timezone.utc):
        logger.critical("CA Certificate expired!")
        exit(1)

    # configure MQTT callbacks
    mq.on_connect = daemon_on_connect
    mq.on_disconnect = daemon_on_disconnect
    mq.on_message = daemon_on_message
    mq.on_publish = daemon_on_publish
    mq.on_subscribe = daemon_on_subscribe
    mq.on_unsubscribe = daemon_on_unsubscribe
    
    mq.message_callback_add('mqtt-ca/+/csr', daemon_sign_cert)
    
    # connect to MQTT
    mq.will_set('mqtt-ca/online', 0, qos=0, retain=True)
    mqconn.connect(mq)
    while mq.is_connected() == False:
        logger.warning("Waiting 5s for MQTT connection")
        time.sleep(5)
        
    # subscribe to CSR topics
    while True:
        (result, mid) = mq.subscribe('mqtt-ca/+/csr', options=mqtt.SubscribeOptions(qos=1))
        if result == mqtt.MQTT_ERR_SUCCESS:
            break
        logger.warning("Waiting 5s for MQTT subscribe")
        time.sleep(5)

    # create background tick thread
    logger.info("Starting ticker thread")
    tick_thread = threading.Thread(target=daemon_ticker, daemon=True)
    tick_thread.start()
    logger.debug("Ticker thread started")

    # create background monitor thread
    logger.info("Starting monitor thread")
    monitor_thread = threading.Thread(target=daemon_monitor, daemon=True)
    monitor_thread.start()
    logger.debug("Monitor thread started")

    # main thread waits forever now, MQTT callbacks handle processing in separate thread
    while True:
        time.sleep(60)
