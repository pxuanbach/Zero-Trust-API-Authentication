#!/bin/bash
set -e

# Update system and install dependencies
yum update -y
yum install -y git curl python3 python3-pip unzip

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf aws awscliv2.zip

# Install Nginx from Amazon Linux Extras
amazon-linux-extras install -y nginx1

# Create application user
useradd -m -s /bin/bash crmapp
mkdir -p /app
chown -R crmapp:crmapp /app

# Clone source code repository
cd /app
sudo git clone --branch feature/proxy-and-cert-agent-modules https://github.com/pxuanbach/Zero-Trust-API-Authentication.git repo
chown -R crmapp:crmapp repo

# Create certificate directories
mkdir -p /app/certs/{crm-app,ca}

# Retrieve certificates from Secrets Manager
aws secretsmanager get-secret-value --secret-id ${project_name}/crm-app/cert --region ${aws_region} \
  --query SecretString --output text > /app/certs/crm-app/crm-app.crt

aws secretsmanager get-secret-value --secret-id ${project_name}/crm-app/key --region ${aws_region} \
  --query SecretString --output text > /app/certs/crm-app/crm-app.key

aws secretsmanager get-secret-value --secret-id ${project_name}/ca/cert --region ${aws_region} \
  --query SecretString --output text > /app/certs/ca/ca.crt

chmod 600 /app/certs/crm-app/*
chmod 644 /app/certs/ca/ca.crt
chown -R crmapp:crmapp /app/certs

# Install Python dependencies
cd /app/repo/src/services/crm-app
pip3 install -r requirements.txt

cp /app/repo/src/services/docker/nginx.conf.template /app/
cp /app/repo/src/services/docker/generate-nginx-conf.sh /app/
cp /app/repo/src/services/docker/cert-reload.sh /app/
chmod +x /app/generate-nginx-conf.sh /app/cert-reload.sh

# Create systemd service for Nginx
systemctl stop nginx || true
systemctl disable nginx || true

cat > /etc/systemd/system/crm-app-nginx.service << 'EOF'
[Unit]
Description=CRM App Nginx SSL Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/app
Environment="SERVICE_NAME=crm-app"
Environment="APP_PORT=8001"
# Generate config to /etc/nginx/nginx.conf
ExecStartPre=/bin/bash /app/generate-nginx-conf.sh
# Start nginx with the generated config
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf -g "daemon off;"
ExecReload=/usr/sbin/nginx -s reload
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service
cat > /etc/systemd/system/crm-app.service << 'EOF'
[Unit]
Description=CRM App FastAPI Service
After=network.target

[Service]
Type=simple
User=crmapp
WorkingDirectory=/app/repo/src/services/crm-app
Environment="SERVICE_NAME=crm-app"
Environment="SERVER_CERT=/app/certs/crm-app/crm-app.crt"
Environment="SERVER_KEY=/app/certs/crm-app/crm-app.key"
Environment="CA_CERT=/app/certs/ca/ca.crt"
ExecStart=/usr/bin/python3 main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable crm-app-nginx
systemctl enable crm-app
systemctl start crm-app-nginx
systemctl start crm-app

# Log startup
echo "CRM App started at $(date)" >> /var/log/crm-app-startup.log

