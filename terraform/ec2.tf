
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# 1. Step CA (Local CA)
resource "aws_instance" "step_ca" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.services_instance_type
  vpc_security_group_ids      = [aws_security_group.services.id]
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  key_name                    = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/step_ca.sh", {
    ca_fingerprint_secret_name = aws_secretsmanager_secret.ca_fingerprint.name
    apisix_public_ip           = aws_eip.apisix.public_ip
    aws_region                 = var.aws_region
    ca_password                = var.ca_password
  }))

  tags = {
    Name = "${var.project_name}-step-ca"
  }

  depends_on = [aws_eip.apisix]
}

# 2. Keycloak
resource "aws_instance" "keycloak" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.services_instance_type
  vpc_security_group_ids      = [aws_security_group.services.id]
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  key_name                    = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/keycloak_docker.sh", {
    aws_region = var.aws_region
  }))

  tags = {
    Name = "${var.project_name}-keycloak"
  }
}

# 3. CRM App
resource "aws_instance" "crm_app" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.services_instance_type
  vpc_security_group_ids      = [aws_security_group.services.id]
  subnet_id                   = aws_subnet.private[0].id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  key_name                    = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/crm_docker.sh", {
    keycloak_private_ip        = aws_instance.keycloak.private_ip
    step_ca_private_ip         = aws_instance.step_ca.private_ip
    apisix_private_ip          = "127.0.0.1"
    ca_fingerprint_secret_name = aws_secretsmanager_secret.ca_fingerprint.name
    apisix_public_ip           = aws_eip.apisix.public_ip
    aws_region                 = var.aws_region
    ca_password                = var.ca_password
  }))

  tags = {
    Name = "${var.project_name}-crm-app"
  }

  depends_on = [aws_instance.keycloak, aws_instance.step_ca, aws_nat_gateway.main, aws_eip.apisix]
}

# 4. APISIX Gateway
resource "aws_instance" "apisix" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.apisix_instance_type
  vpc_security_group_ids      = [aws_security_group.apisix.id]
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  key_name                    = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/apisix_docker.sh", {
    crm_app_private_ip         = aws_instance.crm_app.private_ip
    keycloak_private_ip        = aws_instance.keycloak.private_ip
    step_ca_private_ip         = aws_instance.step_ca.private_ip
    ca_fingerprint_secret_name = aws_secretsmanager_secret.ca_fingerprint.name
    apisix_public_ip           = aws_eip.apisix.public_ip
    aws_region                 = var.aws_region
    ca_password                = var.ca_password
  }))

  tags = {
    Name = "${var.project_name}-apisix"
  }

  depends_on = [aws_instance.crm_app]
}

resource "tls_private_key" "main" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "main" {
  key_name   = "${var.project_name}-keypair"
  public_key = tls_private_key.main.public_key_openssh
}

resource "local_file" "private_key" {
  filename             = "${path.module}/../${var.project_name}-key.pem"
  content              = tls_private_key.main.private_key_pem
  file_permission      = "0600"
  directory_permission = "0700"
}

resource "aws_secretsmanager_secret" "ssh_private_key" {
  name                    = "${var.project_name}/ssh/private-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "ssh_private_key" {
  secret_id     = aws_secretsmanager_secret.ssh_private_key.id
  secret_string = tls_private_key.main.private_key_pem
}

resource "aws_secretsmanager_secret" "ca_fingerprint" {
  name                    = "${var.project_name}/ca/fingerprint"
  recovery_window_in_days = 0
}

resource "aws_eip" "apisix" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-apisix-eip"
  }
}

resource "aws_eip_association" "apisix" {
  instance_id   = aws_instance.apisix.id
  allocation_id = aws_eip.apisix.id
}
