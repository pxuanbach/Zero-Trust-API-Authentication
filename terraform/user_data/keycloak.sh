#!/bin/bash
set -e

# Function: Get Admin Token
get_admin_token() {
  local response
  response=$(curl -s -X POST "http://10.0.10.191:8080/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$ADMIN_USER" \
    -d "password=$ADMIN_PASSWORD" \
    -d "grant_type=password" \
    -d "client_id=admin-cli")
  ADMIN_TOKEN=$(echo "$response" | jq -r '.access_token')
  if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "null" ]; then
    echo "Error: Failed to get admin token!"
    echo "Response: $response"
    exit 1
  fi
}

# Update system
yum update -y
yum install -y java-17-amazon-corretto wget unzip postgresql jq python3 python3-pip git

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf aws awscliv2.zip

# Create keycloak user
useradd -m -s /bin/bash keycloak
mkdir -p /opt/keycloak
chown -R keycloak:keycloak /opt/keycloak

# Download Keycloak
KEYCLOAK_VERSION=23.0.0
cd /opt/keycloak
wget https://github.com/keycloak/keycloak/releases/download/$KEYCLOAK_VERSION/keycloak-$KEYCLOAK_VERSION.tar.gz
tar -xzf keycloak-$KEYCLOAK_VERSION.tar.gz
mv keycloak-$KEYCLOAK_VERSION/* .
rm -rf keycloak-$KEYCLOAK_VERSION.tar.gz keycloak-$KEYCLOAK_VERSION

chown -R keycloak:keycloak /opt/keycloak

# Database configuration
DB_ENDPOINT="${rds_endpoint}"
DB_PORT="${rds_port}"
DB_NAME="${rds_db_name}"
DB_USER="${rds_username}"
DB_PASSWORD="${rds_password}"

# Admin credentials
ADMIN_USER="${keycloak_admin_username}"
ADMIN_PASSWORD="${keycloak_admin_password}"

# Configure Keycloak
cat > /opt/keycloak/conf/keycloak.conf << EOFKC
# Database
db=postgres
db-url=jdbc:postgresql://$DB_ENDPOINT:$DB_PORT/$DB_NAME
db-username=$DB_USER
db-password=$DB_PASSWORD
db-pool-initial-size=10
db-pool-max-size=20

# HTTP
http-enabled=true
http-port=8080
http-host=0.0.0.0

# Hostname
hostname=${alb_dns_name}
hostname-strict=false
hostname-strict-https=false

# Proxy
proxy=edge
forwarded-allow-unencrypted=true

# Logging
log-level=INFO
EOFKC

chown keycloak:keycloak /opt/keycloak/conf/keycloak.conf

# Build Keycloak for production
cd /opt/keycloak
sudo -u keycloak bin/kc.sh build

# Create systemd service
cat > /etc/systemd/system/keycloak.service << EOFSERVICE
[Unit]
Description=Keycloak Authorization Server
After=network.target

[Service]
Type=simple
User=keycloak
Group=keycloak
WorkingDirectory=/opt/keycloak
Environment="KEYCLOAK_ADMIN=$ADMIN_USER"
Environment="KEYCLOAK_ADMIN_PASSWORD=$ADMIN_PASSWORD"
ExecStart=/opt/keycloak/bin/kc.sh start --optimized
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOFSERVICE

# Enable and start Keycloak
systemctl daemon-reload
systemctl enable keycloak
systemctl start keycloak

# Clone repo to get config files
mkdir -p /opt/keycloak-config
cd /opt/keycloak-config
sudo git clone --branch feature/proxy-and-cert-agent-modules https://github.com/pxuanbach/Zero-Trust-API-Authentication.git repo

# Wait for Keycloak to start
echo "Waiting for Keycloak to start..."
# Keycloak 23+ uses /health/ready
until curl -s http://localhost:8080/health/ready > /dev/null; do
  sleep 5
  echo "Waiting for Keycloak..."
done
echo "Keycloak is up."

# Import Realm (if not exists)
get_admin_token
if curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/admin/realms/zero-trust | grep -q "zero-trust"; then
  echo "Realm zero-trust already exists."
else
  echo "Importing Realm..."
  curl -s -X POST "http://localhost:8080/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    --data @/opt/keycloak-config/repo/src/keycloak/realm-config.json
fi

# Get Client UUID
get_admin_token
CLIENT_UUID=$(curl -s -X GET "http://localhost:8080/admin/realms/zero-trust/clients?clientId=test-client" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

AUTHZ_URL="http://localhost:8080/admin/realms/zero-trust/clients/$CLIENT_UUID/authz/resource-server"

# Function to create resource
create_resource() {
  local name="$1"
  local uri="$2"
  local scope="$3"
  get_admin_token
  # Check if resource exists
  local existing_id=$(curl -s -G "$AUTHZ_URL/resource" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    --data-urlencode "name=$name" | jq -r '.[0]._id // empty')
    
  if [ -n "$existing_id" ]; then
    echo "Resource '$name' already exists (ID: $existing_id)"
    echo "$existing_id"
  else
    echo "Creating Resource '$name'..."
    curl -s -X POST "$AUTHZ_URL/resource" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"name\": \"$name\",
        \"uris\": [\"$uri\"],
        \"scopes\": [{\"name\": \"$scope\"}]
      }" | jq -r '._id'
  fi
}
create_permission() {
  local name="$1"
  local resource_id="$2"
  local policy_id="$3"
  get_admin_token
  # Check if permission exists
  local existing_id=$(curl -s -G "$AUTHZ_URL/policy" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    --data-urlencode "name=$name" | jq -r '.[0].id // empty')
    
  if [ -n "$existing_id" ]; then
    echo "Permission '$name' already exists"
  else
    echo "Creating Permission '$name'..."
    curl -s -X POST "$AUTHZ_URL/policy/resource" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"name\": \"$name\",
        \"type\": \"resource\",
        \"logic\": \"POSITIVE\",
        \"decisionStrategy\": \"UNANIMOUS\",
        \"resources\": [\"$resource_id\"],
        \"policies\": [\"$policy_id\"]
      }"
  fi
}
get_admin_token
POLICY_ID=$(curl -s -G "$AUTHZ_URL/policy" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  --data-urlencode "name=Admin Only Policy" | jq -r '.[0].id')
if [ -z "$POLICY_ID" ] || [ "$POLICY_ID" == "null" ]; then
  echo "Error: 'Admin Only Policy' not found!"
else
  RES_ID=$(create_resource "Extension App Delete Resource" "/api/v1/extension-app/*" "delete")
  create_permission "Extension App Delete Permission" "$RES_ID" "$POLICY_ID"
  RES_ID=$(create_resource "CRM App Delete Resource" "/api/v1/crm/*" "delete")
  create_permission "CRM App Delete Permission" "$RES_ID" "$POLICY_ID"
fi

get_admin_token
curl -X PUT "http://localhost:8080/admin/realms/zero-trust" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sslRequired": "none"
  }'

# Log startup
echo "Keycloak started and configured at $(date)" >> /var/log/keycloak-startup.log

