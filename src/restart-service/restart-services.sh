#!/bin/bash
set -e

cd /home/user/zero-trust-lab || exit 1

SERVICES="service-a service-b"

for svc in $SERVICES; do
  FLAG="certs/.restart-$svc"

  if [ -f "$FLAG" ]; then
    echo "[host] Restarting $svc"
    docker compose restart "$svc"
    rm -f "$FLAG"
  fi
done
