#!/bin/bash
SERVICE_NAME="${SERVICE_NAME:-default-service}"
CERT_DIR="/app/certs/${SERVICE_NAME}"

# Wait for certificates to exist
while [ ! -f "$CERT_DIR/${SERVICE_NAME}.crt" ] || [ ! -f "$CERT_DIR/${SERVICE_NAME}.key" ]; do
    echo "Waiting for certificates in $CERT_DIR..."
    sleep 5
done

echo "Certificates found."

# Initial check: Start Nginx if it failed to start initially (due to missing certs)
if ! pgrep nginx > /dev/null; then
    echo "Initial Nginx start after certificates found..."
    nginx -g "daemon off;" &
else
    echo "Nginx is already running."
fi

echo "Starting watch on $CERT_DIR..."

# Watch the directory for any file changes (create, modify, move)
inotifywait -m -r -e modify -e create -e close_write -e moved_to "$CERT_DIR" | while read -r directory events filename; do
    if [[ "$filename" == *"${SERVICE_NAME}.crt"* ]] || [[ "$filename" == *"${SERVICE_NAME}.key"* ]]; then
        echo "Certificate file changed ($events): $filename."
        
        # Check if Nginx is running
        if pgrep nginx > /dev/null; then
            echo "Nginx is running. Reloading..."
            nginx -t 2>/dev/null && nginx -s reload
        fi
    fi
done
