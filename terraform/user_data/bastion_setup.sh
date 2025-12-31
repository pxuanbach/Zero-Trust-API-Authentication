#!/bin/bash
set -e

# Update system
yum update -y
yum install -y git curl python3 python3-pip unzip

# Install Session Manager plugin
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Log startup
echo "Bastion host started at $(date)" >> /var/log/bastion-startup.log

# Fetch SSH Private Key
cd /home/ec2-user
aws secretsmanager get-secret-value \
    --secret-id "${ssh_secret_name}" \
    --region ap-southeast-1 \
    --query 'SecretString' \
    --output text > api-key.pem

# Secure the key
chmod 600 api-key.pem
chown ec2-user:ec2-user api-key.pem

echo "SSH key setup complete." >> /var/log/bastion-startup.log
