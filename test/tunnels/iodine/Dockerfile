FROM alpine:latest

RUN apk add --no-cache iodine

EXPOSE 53/udp

CMD ["sh", "-c", "iodined -f -c -P ${IODINE_PASSWORD} 10.0.0.1 ${IODINE_DOMAIN}"]
