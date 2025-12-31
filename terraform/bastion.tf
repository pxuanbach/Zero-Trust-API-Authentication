resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true
  key_name                    = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/bastion_setup.sh", {
    ssh_secret_name = aws_secretsmanager_secret.ssh_private_key.name
  }))

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


