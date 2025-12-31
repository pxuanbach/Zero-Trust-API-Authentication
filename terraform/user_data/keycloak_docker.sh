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

# Overrides
cat > docker-compose.override.yml <<EOF
services:
  keycloak:
    logging:
      driver: awslogs
      options:
        awslogs-region: "${aws_region}"
        awslogs-group: "/aws/ec2/keycloak"
        awslogs-create-group: "true"
EOF

# Start Keycloak
docker-compose up -d keycloak postgres
