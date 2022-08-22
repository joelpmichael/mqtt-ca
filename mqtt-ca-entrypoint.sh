#!/bin/sh

echo "MQTT-CA ENTRYPOINT RUNNING"
echo "=========================="
echo

# check that /ca structure has been set up
for dir in certs crl csr newcerts private
do
    if [ ! -d "/ca/$dir" ]
    then
        mkdir "/ca/$dir"
    fi
done
chmod 755 /ca/private
touch /ca/index.txt

if [ ! -f /ca/serial ]
then
    echo 1000 > /ca/serial
fi

if [ ! -f /ca/crlnumber ]
then
    echo 1000 > /ca/crlnumber
fi

# check certificate can be verified against the CA
CERT_REQUIRED=false
if ! /usr/bin/openssl verify -CAfile /ca/certs/root.crt /ca/certs/sign.crt > /dev/null 2>&1
then
    CERT_REQUIRED=true
fi

# check public key matches cert
if [ "$CERT_REQUIRED" = "false" ]
then
    /usr/bin/openssl x509 -in /ca/certs/sign.crt -noout -pubkey > /ca/certs/sign.crt.pubkey
    if ! /usr/bin/openssl pkey -in /ca/private/sign.key -pubout | cmp -s /ca/certs/sign.crt.pubkey
    then
        CERT_REQUIRED=true
    fi
fi

if [ "$CERT_REQUIRED" = "true" ]
then
    /usr/bin/openssl genpkey -algorithm ed25519 -out /ca/private/sign.key
    /usr/bin/openssl req -config /ca/openssl.cnf -new -sha3-256 -key /ca/private/sign.key -out /ca/csr/sign.csr -batch
    echo "!!! CERTIFICATE SIGNING REQUEST REQUIRED !!!"
    echo
    echo "Send the following CSR to the CA ROOT:"
    echo
    cat /ca/csr/sign.csr
    echo
    echo "Place the new certificate in sign.crt, then run docker compose up"
    echo
    echo "Container exiting"
    exit 127
fi

echo "CA Certificate Validity Period:"
/usr/bin/openssl x509 -in /ca/certs/sign.crt -noout -dates

# (re-)create certificate chain
cat /ca/certs/sign.crt /ca/certs/root.crt > /ca/certs/sign-root-chain.crt
chmod 644 /ca/certs/sign-root-chain.crt

# check for Mosquitto keys, create if necessary
CERT_REQUIRED=false
if ! /usr/bin/openssl verify -CAfile /ca/certs/sign-root-chain.crt /ca/certs/mosquitto.crt > /dev/null 2>&1
then
    CERT_REQUIRED=true
fi

# check public key matches cert
if [ "$CERT_REQUIRED" = "false" ]
then
    /usr/bin/openssl x509 -in /ca/certs/mosquitto.crt -noout -pubkey > /ca/certs/mosquitto.crt.pubkey
    if ! /usr/bin/openssl pkey -in /ca/private/mosquitto.key -pubout | cmp -s /ca/certs/mosquitto.crt.pubkey
    then
        CERT_REQUIRED=true
    fi
fi

if [ "$CERT_REQUIRED" = "true" ]
then
    /usr/bin/openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out /ca/private/mosquitto.key
    chown 0:1883 /ca/private/mosquitto.key
    chmod 440 /ca/private/mosquitto.key
    /usr/bin/openssl req -config /ca/openssl.cnf -new -sha256 -key /ca/private/mosquitto.key -out /ca/csr/mosquitto.csr -batch -subj "/C=$(grep countryName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/ST=$(grep stateOrProvinceName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/L=$(grep localityName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/O=$(grep 0.organizationName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/OU=$(grep organizationalUnitName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/CN=mosquitto"
    /usr/bin/openssl ca -config /ca/openssl.cnf -extensions server_cert -days 1 -notext -md sha256 -in /ca/csr/mosquitto.csr -out /ca/certs/mosquitto.crt -batch
    chown 0:1883 /ca/certs/mosquitto.crt
    chmod 440 /ca/certs/mosquitto.crt
    cat /ca/certs/mosquitto.crt /ca/certs/sign.crt > /ca/certs/tmp
    cat /ca/certs/tmp > /ca/certs/mosquitto.crt
    if ! /usr/bin/openssl verify -CAfile /ca/certs/sign-root-chain.crt /ca/certs/mosquitto.crt > /dev/null 2>&1
    then
        echo "!!! FAILED TO GENERATE MOSQUITTO PROVISIONING CERTIFICATE !!!"
        echo
        echo "Check validity of certs inside /ca, especially /ca/certs/sign-root-chain.crt"
        echo
        echo "Pausing for 24 hours, then exiting"
        sleep 86400
        exit 126
    fi
fi

# check for MQTT-CA keys, create if necessary
CERT_REQUIRED=false
if ! /usr/bin/openssl verify -CAfile /ca/certs/sign-root-chain.crt /ca/certs/mqtt-ca.crt > /dev/null 2>&1
then
    CERT_REQUIRED=true
fi

# check public key matches cert
if [ "$CERT_REQUIRED" = "false" ]
then
    /usr/bin/openssl x509 -in /ca/certs/mqtt-ca.crt -noout -pubkey > /ca/certs/mqtt-ca.crt.pubkey
    if ! /usr/bin/openssl pkey -in /ca/private/mqtt-ca.key -pubout | cmp -s /ca/certs/mqtt-ca.crt.pubkey
    then
        CERT_REQUIRED=true
    fi
fi

if [ "$CERT_REQUIRED" = "true" ]
then
    /usr/bin/openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out /ca/private/mqtt-ca.key
    chown 0:1883 /ca/private/mqtt-ca.key
    chmod 440 /ca/private/mqtt-ca.key
    /usr/bin/openssl req -config /ca/openssl.cnf -new -sha256 -key /ca/private/mqtt-ca.key -out /ca/csr/mqtt-ca.csr -batch -subj "/C=$(grep countryName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/ST=$(grep stateOrProvinceName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/L=$(grep localityName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/O=$(grep 0.organizationName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/OU=$(grep organizationalUnitName_default /ca/openssl.cnf | cut -d= -f2 | sed 's,^\s*,,')/CN=mqtt-ca"
    /usr/bin/openssl ca -config /ca/openssl.cnf -extensions server_cert -days 1 -notext -md sha256 -in /ca/csr/mqtt-ca.csr -out /ca/certs/mqtt-ca.crt -batch
    chown 0:1883 /ca/certs/mqtt-ca.crt
    chmod 440 /ca/certs/mqtt-ca.crt
    cat /ca/certs/mqtt-ca.crt /ca/certs/sign.crt > /ca/certs/tmp
    cat /ca/certs/tmp > /ca/certs/mqtt-ca.crt
    if ! /usr/bin/openssl verify -CAfile /ca/certs/sign-root-chain.crt /ca/certs/mqtt-ca.crt > /dev/null 2>&1
    then
        echo "!!! FAILED TO GENERATE MQTT-CA PROVISIONING CERTIFICATE !!!"
        echo
        echo "Check validity of certs inside /ca, especially /ca/certs/sign-root-chain.crt"
        echo
        echo "Pausing for 24 hours, then exiting"
        sleep 86400
        exit 126
    fi
fi

/app/mqtt-ca.py monitor /ca/certs/mosquitto.crt /ca/private/mosquitto.key
/app/mqtt-ca.py monitor /ca/certs/mqtt-ca.crt /ca/private/mqtt-ca.key

exec "$@"
