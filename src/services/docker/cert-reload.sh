#!/bin/bash
SERVICE_NAME="${SERVICE_NAME:-default-service}"
WATCH="/app/certs/${SERVICE_NAME}/${SERVICE_NAME}.crt /app/certs/${SERVICE_NAME}/${SERVICE_NAME}.key"

inotifywait -m -e modify $WATCH | while read -r; do
    nginx -t 2>/dev/null && nginx -s reload
done
