# Terraform AWS Configuration - Outputs

output "vpc_id" {
  value       = aws_vpc.main.id
  description = "VPC ID"
}

output "public_subnet_ids" {
  value       = aws_subnet.public[*].id
  description = "Public Subnet IDs"
}

output "private_subnet_ids" {
  value       = aws_subnet.private[*].id
  description = "Private Subnet IDs"
}

output "database_subnet_ids" {
  value       = aws_subnet.database[*].id
  description = "Database Subnet IDs"
}

output "db_subnet_group_name" {
  value       = aws_db_subnet_group.main.name
  description = "Database Subnet Group Name"
}

output "alb_dns_name" {
  value       = aws_lb.main.dns_name
  description = "ALB DNS Name (API Entry Point)"
}

output "bastion_public_ip" {
  value       = aws_instance.bastion.public_ip
  description = "Bastion Host Public IP (for SSH access to private instances)"
}

output "bastion_instance_id" {
  value       = aws_instance.bastion.id
  description = "Bastion Host Instance ID (for SSM Session Manager)"
}

output "alb_arn" {
  value       = aws_lb.main.arn
  description = "ALB ARN"
}

output "apisix_http_target_group_arn" {
  value       = aws_lb_target_group.apisix_http.arn
  description = "APISIX HTTP Target Group ARN"
}

# output "apisix_https_target_group_arn" {
#   value       = aws_lb_target_group.apisix_https.arn
#   description = "APISIX HTTPS Target Group ARN"
# }

output "rds_endpoint" {
  value       = aws_db_instance.keycloak.endpoint
  description = "RDS PostgreSQL Endpoint"
}

output "rds_address" {
  value       = aws_db_instance.keycloak.address
  description = "RDS Address (Hostname)"
}

output "rds_port" {
  value       = aws_db_instance.keycloak.port
  description = "RDS Port"
}

output "rds_database_name" {
  value       = aws_db_instance.keycloak.db_name
  description = "RDS Database Name"
}

output "apisix_asg_name" {
  value       = aws_autoscaling_group.apisix.name
  description = "APISIX Auto Scaling Group Name"
}

output "apisix_desired_capacity" {
  value       = aws_autoscaling_group.apisix.desired_capacity
  description = "APISIX Desired Capacity"
}

output "extension_app_instance_id" {
  value       = aws_instance.extension_app.id
  description = "Extension App EC2 Instance ID"
}

output "extension_app_private_ip" {
  value       = aws_instance.extension_app.private_ip
  description = "Extension App Private IP"
}

output "crm_app_instance_id" {
  value       = aws_instance.crm_app.id
  description = "CRM App EC2 Instance ID"
}

output "crm_app_private_ip" {
  value       = aws_instance.crm_app.private_ip
  description = "CRM App Private IP"
}

output "keycloak_instance_id" {
  value       = aws_instance.keycloak.id
  description = "Keycloak EC2 Instance ID"
}

output "keycloak_private_ip" {
  value       = aws_instance.keycloak.private_ip
  description = "Keycloak Private IP"
}

output "security_group_alb" {
  value       = aws_security_group.alb.id
  description = "ALB Security Group ID"
}

output "security_group_apisix" {
  value       = aws_security_group.apisix.id
  description = "APISIX Security Group ID"
}

output "security_group_services" {
  value       = aws_security_group.services.id
  description = "Services Security Group ID"
}

output "security_group_rds" {
  value       = aws_security_group.rds.id
  description = "RDS Security Group ID"
}

output "security_group_bastion" {
  value       = aws_security_group.bastion.id
  description = "Bastion Security Group ID"
}

output "ec2_instance_profile" {
  value       = aws_iam_instance_profile.ec2_profile.name
  description = "EC2 Instance Profile Name"
}

output "ec2_role_arn" {
  value       = aws_iam_role.ec2_role.arn
  description = "EC2 IAM Role ARN"
}

output "gateway_cert_secret_arn" {
  value       = aws_secretsmanager_secret.gateway_cert.arn
  description = "Gateway Certificate Secret ARN"
}

output "gateway_key_secret_arn" {
  value       = aws_secretsmanager_secret.gateway_key.arn
  description = "Gateway Key Secret ARN"
}

output "ca_cert_secret_arn" {
  value       = aws_secretsmanager_secret.ca_cert.arn
  description = "CA Certificate Secret ARN"
}
