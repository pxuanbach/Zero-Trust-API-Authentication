# ===== SECURITY GROUPS =====

# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# APISIX Security Group
resource "aws_security_group" "apisix" {
  name        = "${var.project_name}-apisix-sg"
  description = "Security group for APISIX API Gateway"
  vpc_id      = aws_vpc.main.id

  # Allow from ALB
  ingress {
    from_port       = 9080
    to_port         = 9080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    from_port       = 9443
    to_port         = 9443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Allow APISIX admin API from private subnets
  ingress {
    from_port   = 9180
    to_port     = 9180
    protocol    = "tcp"
    cidr_blocks = var.private_subnet_cidrs
  }

  # Allow etcd communication (internal)
  ingress {
    from_port = 2379
    to_port   = 2380
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Restrict to IP/VPN in production
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-apisix-sg"
  }
}

# Services (Extension App, CRM App) Security Group
resource "aws_security_group" "services" {
  name        = "${var.project_name}-services-sg"
  description = "Security group for backend services"
  vpc_id      = aws_vpc.main.id

  # Allow mTLS from APISIX on port 8443
  ingress {
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.apisix.id]
  }

  # Allow mTLS between services (Extension App → CRM App)
  ingress {
    from_port = 8443
    to_port   = 8443
    protocol  = "tcp"
    self      = true
  }

  # Allow Keycloak from services (if on same network)
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.apisix.id]
  }

  # Allow ICMP (Ping) from APISIX
  ingress {
    from_port       = -1
    to_port         = -1
    protocol        = "icmp"
    security_groups = [aws_security_group.apisix.id]
  }

  # Allow SSH for debugging
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Restrict in production
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-services-sg"
  }
}

# Keycloak Security Group (if running on EC2, otherwise not needed for RDS)
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-rds-sg"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.main.id

  # Allow from APISIX
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.apisix.id]
  }

  # Allow from services (if needed)
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.services.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-rds-sg"
  }
}
