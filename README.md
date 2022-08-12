# MQTT-CA

Not recommended for general consumption

## Certificates and Keys Required

### Root Certificate

(ref: <https://stackoverflow.com/questions/60689653/openssl-eddsa-specify-key-size>, <https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html>)

1. `mkdir /root/mqtt-ca`
1. `cd /root/mqtt-ca`
1. `mkdir certs crl newcerts private csr`
1. `chmod 700 private`
1. `touch index.txt`
1. `echo 1000 > serial`
1. `cat > openssl.cnf`
1. `openssl genpkey -algorithm ed448 -aes256 -out private/root.key`
1. `chmod 400 private/root.key`
1. `openssl req -config openssl.cnf -key private/root.key -new -x509 -days 10958 -sha3-512 -extensions v3_ca -batch -out certs/root.crt`

### Sign Certificate

1. Obtain CSR on startup of docker container
1. `cd /root/mqtt-ca`
1. `cat > csr/sign.csr`
1. `openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha3-512 -in csr/sign.csr -out certs/sign.crt`

## Configuration Files

1. openssl.cnf: modify `req_distinguished_name` section

## Build & Run

1. `docker build --tag mqtt-ca:latest .`
1. `docker compose up -d`
1. `docker compose down`
