#!/bin/sh
set -e

gen_cert() {
    NAME=$1
    CN=$2
    DIR=$3
    FILENAME=$4

    echo "Generating cert for $NAME ($CN)..."
    mkdir -p $DIR
    
    # Generate Key
    openssl genrsa -out $DIR/$FILENAME.key 2048
    
    # Generate CSR
    openssl req -new -key $DIR/$FILENAME.key -out $DIR/$FILENAME.csr -subj "/CN=$CN"
    
    # Create Extension File for SAN
    echo "subjectAltName=DNS:$CN" > $DIR/$FILENAME.ext
    
    # Sign Certificate
    openssl x509 -req -in $DIR/$FILENAME.csr \
        -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
        -out $DIR/$FILENAME.crt -days 365 \
        -extfile $DIR/$FILENAME.ext
        
    # Cleanup
    rm $DIR/$FILENAME.ext $DIR/$FILENAME.csr
    
    # Set permissions (readable by all)
    chmod 644 $DIR/$FILENAME.key
    chmod 644 $DIR/$FILENAME.crt
}

cd /certs

# Generate for crm-app (service-b)
gen_cert "crm-app" "crm-app" "crm-app" "service-b"

# Generate for extension-app1 (service-a)
gen_cert "extension-app1" "extension-app1" "extension-app1" "service-a"

echo "Certificates regenerated successfully."
