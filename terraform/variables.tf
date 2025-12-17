variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "NT2205-CH191_api"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.0.20.0/24", "10.0.21.0/24"]
}

# ===== EC2 INSTANCES =====
variable "apisix_instance_type" {
  description = "Instance type for APISIX API Gateway"
  type        = string
  default     = "t2.micro"
}

variable "services_instance_type" {
  description = "Instance type for services (Extension App, CRM App)"
  type        = string
  default     = "t2.micro"
}

variable "apisix_desired_count" {
  description = "Desired number of APISIX instances in ASG"
  type        = number
  default     = 2
}

variable "apisix_min_count" {
  description = "Minimum number of APISIX instances in ASG"
  type        = number
  default     = 1
}

variable "apisix_max_count" {
  description = "Maximum number of APISIX instances in ASG"
  type        = number
  default     = 4
}

# ===== RDS =====
variable "rds_db_name" {
  description = "Database name for Keycloak"
  type        = string
  default     = "keycloak"
}

variable "rds_username" {
  description = "RDS master username"
  type        = string
  default     = "keycloak_admin"
}

variable "rds_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}

variable "rds_allocated_storage" {
  description = "Allocated storage for RDS (GB)"
  type        = number
  default     = 20
}

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "rds_multi_az" {
  description = "Enable Multi-AZ for RDS"
  type        = bool
  default     = true
}

# ===== DOCKER IMAGES =====
variable "docker_registry" {
  description = "Docker registry"
  type        = string
  default     = ""
}

variable "apisix_image_tag" {
  description = "APISIX Docker image tag"
  type        = string
  default     = "3.7.0"
}

variable "keycloak_image_tag" {
  description = "Keycloak Docker image tag"
  type        = string
  default     = "23.0"
}

variable "extension_app_image_tag" {
  description = "Extension App Docker image tag"
  type        = string
  default     = "latest"
}

variable "crm_app_image_tag" {
  description = "CRM App Docker image tag"
  type        = string
  default     = "latest"
}

# ===== KEYCLOAK =====
variable "keycloak_admin_username" {
  description = "Keycloak admin username"
  type        = string
  default     = "admin"
}

variable "keycloak_admin_password" {
  description = "Keycloak admin password"
  type        = string
  sensitive   = true
}

variable "keycloak_realm" {
  description = "Keycloak realm name"
  type        = string
  default     = "zero-trust"
}

variable "keycloak_client_id" {
  description = "Keycloak client ID"
  type        = string
  default     = "test-client"
}

variable "keycloak_client_secret" {
  description = "Keycloak client secret"
  type        = string
  sensitive   = true
}

# ===== mTLS CONFIGURATION =====
variable "enable_mtls" {
  description = "Enable mTLS for service-to-service communication"
  type        = bool
  default     = true
}

variable "cert_validity_days" {
  description = "Certificate validity period in days"
  type        = number
  default     = 90
}

variable "ca_common_name" {
  description = "Common Name for Certificate Authority"
  type        = string
  default     = "NT2205-CH191 Root CA"
}

# ===== APISIX CONFIGURATION =====
variable "apisix_admin_key" {
  description = "APISIX Admin API key"
  type        = string
  sensitive   = true
  default     = "edd1c9f034335f136f87ad84b625c8f1"
}
