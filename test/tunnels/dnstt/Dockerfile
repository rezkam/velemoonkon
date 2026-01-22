FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git build-base

WORKDIR /build

# Clone official DNSTT repository
RUN git clone https://www.bamsoftware.com/git/dnstt.git && \
    cd dnstt/dnstt-server && \
    go build -o dnstt-server .

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/dnstt/dnstt-server/dnstt-server /usr/local/bin/

WORKDIR /app

# Generate server keys
RUN mkdir -p /etc/dnstt && \
    dnstt-server -gen-key -privkey-file /etc/dnstt/server.key -pubkey-file /etc/dnstt/server.pub || true

EXPOSE 53/udp

# Start dnstt-server with default configuration
# Domain will be passed via environment variable DNSTT_DOMAIN
CMD ["sh", "-c", "dnstt-server -udp :53 -privkey-file /etc/dnstt/server.key ${DNSTT_DOMAIN:-t.example.com} 127.0.0.1:8000"]
