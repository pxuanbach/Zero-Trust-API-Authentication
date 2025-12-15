FROM alpine:3.19

RUN apk add --no-cache openssl curl

COPY rotate.sh /rotate.sh
RUN chmod +x /rotate.sh

CMD ["/rotate.sh"]