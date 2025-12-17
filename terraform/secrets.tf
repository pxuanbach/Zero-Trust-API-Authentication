# ===== SECRETS MANAGER =====

# Data source to read tls_provider outputs
data "terraform_remote_state" "tls" {
  backend = "local"
  config = {
    path = "${path.module}/../src/tls_provider/terraform.tfstate"
  }
}

# Store gateway certificates
resource "aws_secretsmanager_secret" "gateway_cert" {
  name                    = "${var.project_name}/gateway/cert"
  description             = "Gateway certificate for mTLS"
  recovery_window_in_days = 0

  tags = {
    Name   = "${var.project_name}-gateway-cert"
    MonHoc = "MatMaVaUngDung"
  }
}

resource "aws_secretsmanager_secret_version" "gateway_cert" {
  secret_id = aws_secretsmanager_secret.gateway_cert.id
  secret_string = try(
    data.terraform_remote_state.tls.outputs.service_certificate_contents["gateway"].certificate_pem,
    file("${path.module}/../src/certs/gateway/gateway.crt")
  )
}

resource "aws_secretsmanager_secret" "gateway_key" {
  name                    = "${var.project_name}/gateway/key"
  description             = "Gateway private key for mTLS"
  recovery_window_in_days = 0

  tags = {
    Name   = "${var.project_name}-gateway-key"
    MonHoc = "MatMaVaUngDung"
  }
}

resource "aws_secretsmanager_secret_version" "gateway_key" {
  secret_id = aws_secretsmanager_secret.gateway_key.id
  secret_string = try(
    data.terraform_remote_state.tls.outputs.service_certificate_contents["gateway"].private_key_pem,
    file("${path.module}/../src/certs/gateway/gateway.key")
  )
}

# Store CA Certificate
resource "aws_secretsmanager_secret" "ca_cert" {
  name                    = "${var.project_name}/ca/cert"
  description             = "CA certificate for mTLS verification"
  recovery_window_in_days = 0

  tags = {
    Name   = "${var.project_name}-ca-cert"
    MonHoc = "MatMaVaUngDung"
  }
}

resource "aws_secretsmanager_secret_version" "ca_cert" {
  secret_id = aws_secretsmanager_secret.ca_cert.id
  secret_string = try(
    data.terraform_remote_state.tls.outputs.ca_certificate_pem,
    file("${path.module}/../src/certs/ca/ca.crt")
  )
}

# Keycloak credentials
resource "aws_secretsmanager_secret" "keycloak_credentials" {
  name                    = "${var.project_name}/keycloak/credentials"
  description             = "Keycloak admin credentials"
  recovery_window_in_days = 0

  tags = {
    Name   = "${var.project_name}-keycloak-credentials"
    MonHoc = "MatMaVaUngDung"
  }
}

resource "aws_secretsmanager_secret_version" "keycloak_credentials" {
  secret_id = aws_secretsmanager_secret.keycloak_credentials.id
  secret_string = jsonencode({
    username = var.keycloak_admin_username
    password = var.keycloak_admin_password
  })
}

# APISIX credentials
resource "aws_secretsmanager_secret" "apisix_credentials" {
  name                    = "${var.project_name}/apisix/credentials"
  description             = "APISIX admin API key"
  recovery_window_in_days = 0

  tags = {
    Name   = "${var.project_name}-apisix-credentials"
    MonHoc = "MatMaVaUngDung"
  }
}

resource "aws_secretsmanager_secret_version" "apisix_credentials" {
  secret_id = aws_secretsmanager_secret.apisix_credentials.id
  secret_string = jsonencode({
    admin_key = "edd1c9f034335f136f87ad84b625c8f1"
  })
}

# Keycloak client credentials
resource "aws_secretsmanager_secret" "keycloak_client" {
  name                    = "${var.project_name}/keycloak/client"
  description             = "Keycloak client credentials"
  recovery_window_in_days = 0

  tags = {
    Name   = "${var.project_name}-keycloak-client"
    MonHoc = "MatMaVaUngDung"
  }
}

resource "aws_secretsmanager_secret_version" "keycloak_client" {
  secret_id = aws_secretsmanager_secret.keycloak_client.id
  secret_string = jsonencode({
    client_id     = var.keycloak_client_id
    client_secret = var.keycloak_client_secret
  })
}
