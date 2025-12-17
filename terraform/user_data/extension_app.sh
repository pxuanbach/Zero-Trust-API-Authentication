#!/bin/bash
set -e

# Update system and install dependencies
yum update -y
yum install -y git curl python3 python3-pip unzip gettext

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf aws awscliv2.zip

# Install Nginx from Amazon Linux Extras
amazon-linux-extras install -y nginx1

# Create application user
useradd -m -s /bin/bash extapp
mkdir -p /app
chown -R extapp:extapp /app

# Clone source code repository
cd /app
sudo git clone --branch feature/proxy-and-cert-agent-modules https://github.com/pxuanbach/Zero-Trust-API-Authentication.git repo
chown -R extapp:extapp repo

# Create certificate directories
mkdir -p /app/certs/{extension-app1,ca}

# Retrieve certificates from Secrets Manager
aws secretsmanager get-secret-value --secret-id ${project_name}/extension-app1/cert --region ${aws_region} \
  --query SecretString --output text > /app/certs/extension-app1/extension-app1.crt
aws secretsmanager get-secret-value --secret-id ${project_name}/extension-app1/key --region ${aws_region} \
  --query SecretString --output text > /app/certs/extension-app1/extension-app1.key

aws secretsmanager get-secret-value --secret-id ${project_name}/ca/cert --region ${aws_region} \
  --query SecretString --output text > /app/certs/ca/ca.crt

chmod 600 /app/certs/extension-app1/*
chmod 644 /app/certs/ca/ca.crt
chown -R extapp:extapp /app/certs
# Install Python dependencies
cd /app/repo/src/services/extension-app1
pip3 install -r requirements.txt


cp /app/repo/src/services/docker/nginx.conf.template /app/
cp /app/repo/src/services/docker/generate-nginx-conf.sh /app/
cp /app/repo/src/services/docker/cert-reload.sh /app/
chmod +x /app/generate-nginx-conf.sh /app/cert-reload.sh

# Create systemd service for Nginx
systemctl stop nginx || true
systemctl disable nginx || true

cat > /etc/systemd/system/extension-app-nginx.service << 'EOF'
[Unit]
Description=Extension App Nginx SSL Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/app
Environment="SERVICE_NAME=extension-app1"
Environment="APP_PORT=8000"
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

# Update /etc/hosts
echo "${crm_app_private_ip} crm-app" | sudo tee -a /etc/hosts

# Create systemd service for FastAPI app
cat > /etc/systemd/system/extension-app.service << 'EOF'
[Unit]
Description=Extension App FastAPI Service
After=network.target extension-app-nginx.service

[Service]
Type=simple
User=extapp
WorkingDirectory=/app/repo/src/services/extension-app1
Environment="SERVICE_NAME=extension-app1"
Environment="CRM_APP_URL=https://crm-app:8443"
Environment="SERVER_CERT=/app/certs/extension-app1/extension-app1.crt"
Environment="SERVER_KEY=/app/certs/extension-app1/extension-app1.key"
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
systemctl enable extension-app-nginx
systemctl enable extension-app
systemctl start extension-app-nginx
systemctl start extension-app

# Log startup
echo "Extension App (Nginx + FastAPI) started at $(date)" >> /var/log/extension-app-startup.log

