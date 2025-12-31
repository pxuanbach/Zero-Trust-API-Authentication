#!/bin/bash
sudo yum update -y
sudo amazon-linux-extras install docker -y
sudo service docker start
sudo usermod -a -G docker ec2-user
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose

# Install git
sudo yum install -y git

# Install Step CLI
sudo rpm -ivh https://github.com/smallstep/cli/releases/download/v0.24.4/step-cli_0.24.4_amd64.rpm

# Clone repo
cd /home/ec2-user
git clone --branch feature/proxy-and-cert-agent-modules https://github.com/pxuanbach/Zero-Trust-API-Authentication.git
chown -R ec2-user:ec2-user Zero-Trust-API-Authentication
cd Zero-Trust-API-Authentication

# Fix ports for direct EC2 access
sed -i 's/"8404:8443"/"8443:8443"/g' src/services.yml

# Map step-ca for resolution
if ! grep -q "step-ca" /etc/hosts; then
  echo "${step_ca_private_ip} step-ca" | sudo tee -a /etc/hosts
fi

# Fetch Fingerprint
echo "Fetching CA Fingerprint..."
while true; do
  CA_FINGERPRINT=$(aws secretsmanager get-secret-value --secret-id "${ca_fingerprint_secret_name}" --region ap-southeast-1 --query 'SecretString' --output text 2>/dev/null)
  if [ ! -z "$CA_FINGERPRINT" ]; then
    echo "Fetched Fingerprint: $CA_FINGERPRINT"
    break
  fi
  sleep 10
done
export CA_FINGERPRINT=$CA_FINGERPRINT

# Bootstrap Certificates for CRM App
echo "Bootstrapping Certificates..."
mkdir -p certs/crm-app certs/ca
chmod -R 777 certs

# Get Root CA
step ca root certs/ca/ca.crt --ca-url https://step-ca:9000 --fingerprint $CA_FINGERPRINT

# Generate Cert
echo "${ca_password}" > /tmp/pwd
TOKEN=$(step ca token crm-app --password-file /tmp/pwd --ca-url https://step-ca:9000 --root certs/ca/ca.crt --san crm-app --san localhost --san 127.0.0.1)
step ca certificate crm-app certs/crm-app/crm-app.crt certs/crm-app/crm-app.key --token $TOKEN --ca-url https://step-ca:9000 --root certs/ca/ca.crt

# Overrides
cat > docker-compose.override.yml <<EOF
services:
  crm-app:
    extra_hosts:
      - "keycloak:${keycloak_private_ip}"
      - "step-ca:${step_ca_private_ip}"
      - "apisix:${apisix_private_ip}"
    volumes:
      - ./certs:/app/certs
    environment:
      - SERVER_CERT=/app/certs/crm-app/crm-app.crt
      - SERVER_KEY=/app/certs/crm-app/crm-app.key
      - CA_CERT=/app/certs/ca/ca.crt
    logging:
      driver: awslogs
      options:
        awslogs-region: "${aws_region}"
        awslogs-group: "/aws/ec2/crm-app"
        awslogs-create-group: "true"
EOF

docker-compose up -d crm-app
