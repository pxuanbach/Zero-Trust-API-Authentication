terraform {
  required_version = ">= 1.0"

  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

# ===== ROOT CA SETUP =====

# Generate CA private key (4096-bit RSA for security)
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Create self-signed CA certificate
resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = var.ca_common_name
    organization = var.organization_name
    country      = var.country_code
    province     = var.province
    locality     = var.locality
  }

  validity_period_hours = var.ca_validity_hours

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "key_encipherment",
    "digital_signature"
  ]

  is_ca_certificate = true
}

# ===== LOCAL FILE OUTPUT =====

# Output CA certificate
resource "local_file" "ca_cert" {
  content         = tls_self_signed_cert.ca.cert_pem
  filename        = "${path.module}/../certs/ca/ca.crt"
  file_permission = "0644"
}

# Output CA private key (sensitive - restricted permissions)
resource "local_sensitive_file" "ca_key" {
  content         = tls_private_key.ca.private_key_pem
  filename        = "${path.module}/../certs/ca/ca.key"
  file_permission = "0600"
}
