#!/bin/bash
set -e

/app/generate-nginx-conf.sh
nginx -g "daemon off;" &
python main.py &
/app/cert-reload.sh &

trap "kill 0" SIGTERM SIGINT
wait
