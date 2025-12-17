# ===== CA CONFIGURATION =====

variable "ca_common_name" {
  description = "Common Name for the Certificate Authority"
  type        = string
  default     = "NT2205-CH191 Root CA"
}

variable "organization_name" {
  description = "Organization name for certificates"
  type        = string
  default     = "NT2205-CH191"
}

variable "country_code" {
  description = "Country code for certificate subject"
  type        = string
  default     = "VN"
}

variable "province" {
  description = "Province/State for certificate subject"
  type        = string
  default     = "Ho Chi Minh"
}

variable "locality" {
  description = "City/Locality for certificate subject"
  type        = string
  default     = "Ho Chi Minh City"
}

variable "ca_validity_hours" {
  description = "Validity period for CA certificate in hours"
  type        = number
  default     = 87600 # 10 years
}

# ===== SERVICE CERTIFICATES CONFIGURATION =====

variable "cert_validity_hours" {
  description = "Validity period for service certificates in hours"
  type        = number
  default     = 2160 # 90 days
}

variable "services_config" {
  description = "Configuration for service certificates"
  type = map(object({
    common_name = string
    dns_names   = list(string)
    ip_addresses = list(string)
    directory   = string
  }))
  
  default = {
    gateway = {
      common_name  = "apisix.local"
      dns_names    = ["host.docker.internal", "localhost", "apisix", "*.elb.amazonaws.com"]
      ip_addresses = ["127.0.0.1"]
      directory    = "gateway"
    }
    extension-app1 = {
      common_name  = "extension-app1.local"
      dns_names    = ["host.docker.internal", "localhost", "extension-app1", "*.elb.amazonaws.com"]
      ip_addresses = ["127.0.0.1"]
      directory    = "extension-app1"
    }
    crm-app = {
      common_name  = "crm-app.local"
      dns_names    = ["host.docker.internal", "localhost", "crm-app", "*.elb.amazonaws.com"]
      ip_addresses = ["127.0.0.1"]
      directory    = "crm-app"
    }
  }
}

# ===== ENABLE/DISABLE CERTIFICATE GENERATION =====

variable "generate_certificates" {
  description = "Enable or disable certificate generation"
  type        = bool
  default     = true
}
