FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssl \
    inotify-tools \
    gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY ./extension-app1/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./extension-app1/main.py .

COPY ../docker/entrypoint.sh /app/entrypoint.sh
COPY ../docker/cert-reload.sh /app/cert-reload.sh
COPY ../docker/generate-nginx-conf.sh /app/generate-nginx-conf.sh
COPY ../docker/nginx.conf.template /app/nginx.conf.template

RUN chmod +x /app/entrypoint.sh /app/cert-reload.sh /app/generate-nginx-conf.sh

EXPOSE 8000 8443

ENV SERVICE_NAME=extension-app1
ENV APP_PORT=8000

# Run both FastAPI and Nginx via entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
