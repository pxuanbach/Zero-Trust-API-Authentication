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

# Clone repo
cd /home/ec2-user
git clone --branch feature/proxy-and-cert-agent-modules https://github.com/pxuanbach/Zero-Trust-API-Authentication.git
chown -R ec2-user:ec2-user Zero-Trust-API-Authentication
cd Zero-Trust-API-Authentication

cat > docker-compose.override.yml <<EOF
services:
  apisix:
    extra_hosts:
      - "crm-app:${crm_app_private_ip}"
      - "keycloak:${keycloak_private_ip}"
      - "step-ca:${step_ca_private_ip}"
    logging:
      driver: awslogs
      options:
        awslogs-region: "${aws_region}"
        awslogs-group: "/aws/ec2/apisix-gateway"
        awslogs-create-group: "true"
EOF


sudo yum install -y python3 python3-pip
pip3 install requests "urllib3<2"

sudo rpm -ivh https://github.com/smallstep/cli/releases/download/v0.24.4/step-cli_0.24.4_amd64.rpm

mkdir -p certs/certs
chmod -R 777 certs # Ensure APISIX container can read

docker-compose up -d apisix apisix-dashboard

# Run Config Loader on Host
echo "Running Config Loader on Host..."
export STEP_CA_URL="https://step-ca:9000"
# APISIX Admin is mapped to 9180 on host
export APISIX_ADMIN_URL="http://127.0.0.1:9180/apisix/admin/routes"
export APISIX_SSL_URL="http://127.0.0.1:9180/apisix/admin/ssls"
export ADMIN_KEY="edd1c9f034335f136f87ad84b625c8f1"
export CA_PASSWORD="${ca_password}"
export APISIX_PUBLIC_IP="${apisix_public_ip}"

# Execute scripts from repo
python3 src/apisix/init_ssl.py
python3 src/apisix/init_routes.py

if ! grep -q "step-ca" /etc/hosts; then
  echo "${step_ca_private_ip} step-ca" | sudo tee -a /etc/hosts
fi

python3 src/apisix/init_ssl.py
python3 src/apisix/init_routes.py

