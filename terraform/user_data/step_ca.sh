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

# Step-CA: Map 9000:9000 instead of 9001:9000
sed -i 's/"9001:9000"/"9000:9000"/g' src/step-ca.yml
# Inject Public IP into Step-CA DNS names for Audience validation
sed -i "s/localhost,step-ca,apisix/localhost,step-ca,apisix,${apisix_public_ip}/g" src/step-ca.yml

# Overrides
cat > docker-compose.override.yml <<EOF
services:
  step-ca:
    logging:
      driver: awslogs
      options:
        awslogs-region: "${aws_region}"
        awslogs-group: "/aws/ec2/step-ca"
        awslogs-create-group: "true"
EOF

docker-compose up -d step-ca

echo "Waiting for Step-CA..."
until curl -sk https://localhost:9000/health; do
  sleep 5
done

# Extract fingerprint
echo "Extracting Fingerprint..."
FINGERPRINT=$(docker exec step-ca step certificate fingerprint /home/step/certs/root_ca.crt)
echo "Fingerprint: $FINGERPRINT"

# Store in Secrets Manager
aws secretsmanager put-secret-value \
    --secret-id "${ca_fingerprint_secret_name}" \
    --secret-string "$FINGERPRINT" \
    --region ap-southeast-1

echo "Fingerprint stored in Secrets Manager."
