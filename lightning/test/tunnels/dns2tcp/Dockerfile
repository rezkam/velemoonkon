FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y dns2tcp && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/dns2tcp

COPY dns2tcpd.conf /etc/dns2tcp/

EXPOSE 53/udp
EXPOSE 53/tcp

CMD ["dns2tcpd", "-F", "-f", "/etc/dns2tcp/dns2tcpd.conf"]
