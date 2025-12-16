infras:
	docker compose -f ./src/docker-compose.yml -f ./src/dbs.yml -f ./src/services.yml up -d

validate-infras:
	cd terraform && terraform validate

plan-infras:
	cd terraform && terraform plan -var-file="env/dev.tfvars" -out=tfplan

tf-base-infras:
	cd terraform && \
	terraform apply -var-file="env/dev.tfvars" \
	-target="module.vpc" \
	-target="aws_security_group.apisix" \
	-target="aws_security_group.services" \
	-target="aws_iam_role.ec2

tf-all:
	cd terraform && \
	terraform apply -var-file="env/dev.tfvars"

tf-crm-app:
	cd terraform && \
	terraform apply -var-file="env/dev.tfvars" -target="aws_instance.crm_app"

tf-crm-app-d:
	cd terraform && \
	terraform destroy -var-file="env/dev.tfvars" -target="aws_instance.crm_app"

tf-ext-app:
	cd terraform && \
	terraform apply -var-file="env/dev.tfvars" -target="aws_instance.extension_app"

tf-ext-app-d:
	cd terraform && \
	terraform destroy -var-file="env/dev.tfvars" -target="aws_instance.extension_app"

tf-apisix:
	cd terraform && \
	terraform apply -var-file="env/dev.tfvars" -target="aws_autoscaling_group.apisix" -target="aws_lb.apisix"

tf-apisix-d:
	cd terraform && \
	terraform destroy -var-file="env/dev.tfvars" -target="aws_autoscaling_group.apisix" -target="aws_lb.apisix"

tf-keycloak:
	cd terraform && \
	terraform apply -var-file="env/dev.tfvars" -target="aws_instance.keycloak"

tf-keycloak-d:
	cd terraform && \
	terraform destroy -var-file="env/dev.tfvars" -target="aws_instance.keycloak"

rm-keys:
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/gateway/cert" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/gateway/key" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/ca/cert" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/keycloak/credentials" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/apisix/credentials" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/keycloak/client" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/extension-app1/cert" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/extension-app1/key" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/crm-app/cert" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/crm-app/key" --force-delete-without-recovery --region us-east-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/ssh/private-key" --force-delete-without-recovery --region us-east-1
	@echo "All secrets deleted"

common:
	sudo tail -n 100 /var/log/cloud-init-output.log | grep -i "error\|failed" -A 5

	cat /tmp/rockspec/apisix-master-0.rockspec

	luarocks list | grep luasec

	/usr/local/apisix/bin/apisix version

	systemctl status apisix