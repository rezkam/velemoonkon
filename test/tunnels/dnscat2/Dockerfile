FROM ruby:3.1-alpine

RUN apk add --no-cache git build-base

WORKDIR /app
RUN git clone https://github.com/iagox86/dnscat2.git && \
    cd dnscat2/server && \
    gem install bundler && \
    bundle install

WORKDIR /app/dnscat2/server

EXPOSE 53/udp

CMD ["sh", "-c", "ruby dnscat2.rb --dns domain=${DNSCAT2_DOMAIN},host=0.0.0.0,port=53 --security=open --no-cache"]
