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

variable "apisix_image_tag" {
  description = "APISIX Docker image tag"
  type        = string
  default     = "3.7.0"
}

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

# ===== APISIX CONFIGURATION =====
variable "apisix_admin_key" {
  description = "APISIX Admin API key"
  type        = string
  sensitive   = true
  default     = "edd1c9f034335f136f87ad84b625c8f1"
}

variable "ca_password" {
  description = "Password for Step CA Provisioner"
  type        = string
  sensitive   = true
}

variable "my_ip" {
  description = "Your local IP address"
  type        = string
}
