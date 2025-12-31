# ===== SERVICE PRIVATE KEYS =====

resource "tls_private_key" "service" {
  for_each = var.generate_certificates ? var.services_config : {}

  algorithm = "RSA"
  rsa_bits  = 2048

  # algorithm = "ED25519"

  # algorithm   = "ECDSA"
  # ecdsa_curve = "P256"
}

# ===== SERVICE CERTIFICATE REQUESTS =====

resource "tls_cert_request" "service" {
  for_each = var.generate_certificates ? var.services_config : {}

  private_key_pem = tls_private_key.service[each.key].private_key_pem

  subject {
    common_name  = each.value.common_name
    organization = var.organization_name
    country      = var.country_code
    province     = var.province
    locality     = var.locality
  }

  dns_names    = each.value.dns_names
  ip_addresses = each.value.ip_addresses
}

# ===== CA-SIGNED SERVICE CERTIFICATES =====

resource "tls_locally_signed_cert" "service" {
  for_each = var.generate_certificates ? var.services_config : {}

  cert_request_pem   = tls_cert_request.service[each.key].cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = var.cert_validity_hours

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
    "client_auth"
  ]
}

# ===== LOCAL FILE OUTPUT FOR SERVICES =====

# Output service certificates
resource "local_file" "service_cert" {
  for_each = var.generate_certificates ? var.services_config : {}

  content         = tls_locally_signed_cert.service[each.key].cert_pem
  filename        = "${path.module}/../certs/${each.value.directory}/${each.key}.crt"
  file_permission = "0644"
}

# Output service private keys
resource "local_sensitive_file" "service_key" {
  for_each = var.generate_certificates ? var.services_config : {}

  content         = tls_private_key.service[each.key].private_key_pem
  filename        = "${path.module}/../certs/${each.value.directory}/${each.key}.key"
  file_permission = "0600"
}
