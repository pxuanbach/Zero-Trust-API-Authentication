# Store service certificates in Secrets Manager
resource "aws_secretsmanager_secret" "extension_app_cert" {
  name                    = "${var.project_name}/extension-app1/cert"
  description             = "Extension App certificate for mTLS"
  recovery_window_in_days = 7

  tags = {
    Name    = "${var.project_name}-extension-app1-cert"
    Service = "extension-app1"
  }
}

resource "aws_secretsmanager_secret" "extension_app_key" {
  name                    = "${var.project_name}/extension-app1/key"
  description             = "Extension App private key for mTLS"
  recovery_window_in_days = 7

  tags = {
    Name    = "${var.project_name}-extension-app1-key"
    Service = "extension-app1"
  }
}

resource "aws_secretsmanager_secret" "crm_app_cert" {
  name                    = "${var.project_name}/crm-app/cert"
  description             = "CRM App certificate for mTLS"
  recovery_window_in_days = 7

  tags = {
    Name    = "${var.project_name}-crm-app-cert"
    Service = "crm-app"
  }
}

resource "aws_secretsmanager_secret" "crm_app_key" {
  name                    = "${var.project_name}/crm-app/key"
  description             = "CRM App private key for mTLS"
  recovery_window_in_days = 7

  tags = {
    Name    = "${var.project_name}-crm-app-key"
    Service = "crm-app"
  }
}

# IAM policy to allow EC2 instances to read certificates
resource "aws_iam_policy" "secrets_read" {
  name        = "${var.project_name}-secrets-read-policy"
  description = "Allow EC2 instances to read certificates from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.gateway_cert.arn,
          aws_secretsmanager_secret.gateway_key.arn,
          aws_secretsmanager_secret.ca_cert.arn,
          aws_secretsmanager_secret.extension_app_cert.arn,
          aws_secretsmanager_secret.extension_app_key.arn,
          aws_secretsmanager_secret.crm_app_cert.arn,
          aws_secretsmanager_secret.crm_app_key.arn
        ]
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-secrets-read-policy"
  }
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "ec2_secrets_read" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.secrets_read.arn
}
