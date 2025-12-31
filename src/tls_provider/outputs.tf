# ===================================================
# Outputs - Certificate Paths and Metadata
# ===================================================

# ===== CA OUTPUTS =====

output "ca_certificate_path" {
  description = "Path to CA certificate"
  value       = var.generate_certificates ? local_file.ca_cert.filename : null
}

output "ca_private_key_path" {
  description = "Path to CA private key (SENSITIVE)"
  value       = var.generate_certificates ? local_sensitive_file.ca_key.filename : null
  sensitive   = true
}

output "ca_certificate_pem" {
  description = "CA certificate in PEM format"
  value       = var.generate_certificates ? tls_self_signed_cert.ca.cert_pem : null
}

output "ca_validity_start_time" {
  description = "CA certificate validity start time"
  value       = var.generate_certificates ? tls_self_signed_cert.ca.validity_start_time : null
}

output "ca_validity_end_time" {
  description = "CA certificate validity end time"
  value       = var.generate_certificates ? tls_self_signed_cert.ca.validity_end_time : null
}

# ===== SERVICE CERTIFICATE OUTPUTS =====

output "service_certificate_paths" {
  description = "Map of service names to certificate paths"
  value = var.generate_certificates ? {
    for service, config in var.services_config :
    service => {
      certificate  = local_file.service_cert[service].filename
      private_key  = local_sensitive_file.service_key[service].filename
      directory    = config.directory
      common_name  = config.common_name
      dns_names    = config.dns_names
    }
  } : {}
}

output "service_validity_info" {
  description = "Validity information for service certificates"
  value = var.generate_certificates ? {
    for service, cert in tls_locally_signed_cert.service :
    service => {
      validity_start_time = cert.validity_start_time
      validity_end_time   = cert.validity_end_time
      cert_pem_sha256     = sha256(cert.cert_pem)
    }
  } : {}
}

# ===== SUMMARY OUTPUT =====

output "certificates_generated" {
  description = "Summary of generated certificates"
  value = var.generate_certificates ? {
    ca = {
      path       = local_file.ca_cert.filename
      valid_from = tls_self_signed_cert.ca.validity_start_time
      valid_to   = tls_self_signed_cert.ca.validity_end_time
    }
    services = {
      count = length(var.services_config)
      names = keys(var.services_config)
    }
    base_directory = "${path.module}/../certs"
  } : null
}
