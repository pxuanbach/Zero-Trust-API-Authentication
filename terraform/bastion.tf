resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true
  key_name = aws_key_pair.main.key_name

  user_data = base64encode(<<-EOF
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
  EOF
  )

  tags = {
    Name = "${var.project_name}-bastion"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "bastion" {
  name        = lower("${var.project_name}-bastion-sg")
  description = "Security group for Bastion host"
  vpc_id      = aws_vpc.main.id

  # Allow SSH from anywhere (0.0.0.0/0 - restrict this in production!)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-bastion-sg"
  }
}

# Allow SSH from Bastion to APISIX
resource "aws_security_group_rule" "bastion_to_apisix_ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = aws_security_group.apisix.id
  source_security_group_id = aws_security_group.bastion.id
  description              = "SSH from Bastion to APISIX"
}

# Allow SSH from Bastion to Services
resource "aws_security_group_rule" "bastion_to_services_ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = aws_security_group.services.id
  source_security_group_id = aws_security_group.bastion.id
  description              = "SSH from Bastion to Services"
}

# Allow SSH from Bastion to RDS (optional, for debugging)
resource "aws_security_group_rule" "bastion_to_rds_ssh" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.rds.id
  source_security_group_id = aws_security_group.bastion.id
  description              = "PostgreSQL from Bastion (debugging)"
}
