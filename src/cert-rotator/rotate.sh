#!/bin/sh
set -e

###############################################################
# CONFIG
###############################################################

CERT_ROOT="/certs"

CA_DIR="$CERT_ROOT/ca"
CA_CERT="$CA_DIR/ca.crt"
CA_KEY="$CA_DIR/ca.key"

EXT_FILE="$CERT_ROOT/openssl-ext.cnf"

SERVICES="service-a service-b"

CERT_DAYS=7
ROTATE_BEFORE_DAYS=2

###############################################################
# UTILS
###############################################################

log () {
  echo "[rotator] $1"
}

###############################################################
# 1. Ensure CA exists (auto-gen once)
###############################################################

ensure_ca () {
  if [ -f "$CA_CERT" ] && [ -f "$CA_KEY" ]; then
    log "CA exists"
    return
  fi

  log "CA not found → generating new CA"

  mkdir -p "$CA_DIR"

  openssl genrsa -out "$CA_KEY" 4096

  openssl req -x509 -new -nodes \
    -key "$CA_KEY" \
    -sha256 \
    -days 3650 \
    -subj "/CN=internal-root-ca" \
    -out "$CA_CERT"

  chmod 600 "$CA_KEY"
  chmod 644 "$CA_CERT"

  log "CA generated"
}

###############################################################
# 2. Ensure openssl-ext.cnf
###############################################################

ensure_extfile () {
  if [ -f "$EXT_FILE" ]; then
    return
  fi

  log "openssl-ext.cnf not found → generating"

  cat > "$EXT_FILE" <<EOF
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = service-a
DNS.2 = service-b
EOF
}

###############################################################
# 3. Check cert expiry
###############################################################

cert_need_rotate () {
  CERT="$1"

  if [ ! -f "$CERT" ]; then
    return 0
  fi

  EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)
  EXPIRY_TS=$(date -d "$EXPIRY_DATE" +%s)
  NOW_TS=$(date +%s)

  REMAIN_DAYS=$(( (EXPIRY_TS - NOW_TS) / 86400 ))

  [ "$REMAIN_DAYS" -le "$ROTATE_BEFORE_DAYS" ]
}

###############################################################
# 4. Rotate cert and signal restart
###############################################################

rotate_cert () {
  SERVICE="$1"

  SERVICE_DIR="$CERT_ROOT/$SERVICE"
  CERT="$SERVICE_DIR/$SERVICE.crt"
  KEY="$SERVICE_DIR/$SERVICE.key"
  CSR="$SERVICE_DIR/$SERVICE.csr"

  mkdir -p "$SERVICE_DIR"

  log "Checking $SERVICE"

  if ! cert_need_rotate "$CERT"; then
    log "$SERVICE cert still valid"
    return
  fi

  log "Rotating cert for $SERVICE"

  openssl genrsa -out "$KEY" 2048

  openssl req -new \
    -key "$KEY" \
    -subj "/CN=$SERVICE" \
    -out "$CSR"

  openssl x509 -req \
    -in "$CSR" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$CERT" \
    -days "$CERT_DAYS" \
    -sha256 \
    -extfile "$EXT_FILE" \
    -extensions v3_req

  rm -f "$CSR"

  chmod 600 "$KEY"
  chmod 644 "$CERT"

  # Signal host to restart service
  touch "$CERT_ROOT/.restart-$SERVICE"

  log "Restart signal created for $SERVICE"
}

###############################################################
# MAIN
###############################################################

log "Starting certificate rotation"

ensure_ca
ensure_extfile

for svc in $SERVICES; do
  rotate_cert "$svc"
done

log "Rotation finished"
