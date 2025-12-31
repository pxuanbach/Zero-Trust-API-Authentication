output "vpc_id" {
  value       = aws_vpc.main.id
  description = "VPC ID"
}

output "apisix_public_ip" {
  value       = aws_eip.apisix.public_ip
  description = "APISIX Gateway Public IP"
}

output "bastion_public_ip" {
  value       = aws_instance.bastion.public_ip
  description = "Bastion Host Public IP"
}

# Private IPs
output "apisix_private_ip" {
  value = aws_instance.apisix.private_ip
}

output "step_ca_private_ip" {
  value = aws_instance.step_ca.private_ip
}

output "crm_app_private_ip" {
  value = aws_instance.crm_app.private_ip
}

output "keycloak_private_ip" {
  value = aws_instance.keycloak.private_ip
}
