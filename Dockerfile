# syntax=docker/dockerfile:1
FROM python:3-alpine

VOLUME [ "/ca" ]

RUN mkdir /app /ca
RUN apk add openssl build-base libffi-dev

COPY --chmod=755 mqtt-ca.py mqtt-ca-entrypoint.sh mosquitto_security.json /app/
COPY MQTT_CA /app/MQTT_CA

RUN pip install --upgrade pip
RUN pip install paho-mqtt cryptography

ENTRYPOINT [ "/app/mqtt-ca-entrypoint.sh" ]
CMD [ "/app/mqtt-ca.py", "--config=/app/config.json", "--log-level=INFO", "--log-dest=/ca/daemon.log", "daemon" ]
