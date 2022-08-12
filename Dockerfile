# syntax=docker/dockerfile:1
FROM python:3-alpine

VOLUME [ "/ca" ]

RUN mkdir /app /ca
RUN apk add openssl

COPY --chmod=755 mqtt-ca.py mqtt-ca-entrypoint.sh /app/
COPY MQTT-CA /app/MQTT-CA

ENTRYPOINT [ "/app/mqtt-ca-entrypoint.sh" ]
CMD [ "/app/mqtt-ca.py" ]
