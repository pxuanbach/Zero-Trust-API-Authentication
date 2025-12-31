#!/bin/bash
export SERVICE_NAME="${SERVICE_NAME:-default}"
export APP_PORT="${APP_PORT:-8000}"
envsubst '$SERVICE_NAME,$APP_PORT' < /app/nginx.conf.template > /etc/nginx/nginx.conf
