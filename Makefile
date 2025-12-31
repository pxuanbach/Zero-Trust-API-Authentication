infras:
	docker compose up -d

validate:
	cd terraform && terraform validate

init-ext-certs:
	docker compose exec -e CA_PASSWORD=secure-ca-password extension-app1 python bootstrap_certs.py

plan: rm-keys
	cd terraform && terraform plan -var-file="env/dev.tfvars" -out=tfplan

apply:
	cd terraform && terraform apply -var-file="env/dev.tfvars"

apply-plan:
	cd terraform && terraform apply "tfplan"
# 	-var-file="env/dev.tfvars"
# 	-replace="aws_instance.apisix"

destroy:
	cd terraform && terraform destroy -var-file="env/dev.tfvars"

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

build-images:
	docker build -t pxuanbach/zt:apisix-config-loader -f src/services.yml 

rm-keys:
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/ssh/private-key" --force-delete-without-recovery --region ap-southeast-1
	@aws secretsmanager delete-secret --secret-id "NT2205-CH191-api/ca/fingerprint" --force-delete-without-recovery --region ap-southeast-1
	@echo "All secrets deleted"

refresh-keypair:
	icacls ./NT2205-CH191-api-key.pem /reset
	icacls ./NT2205-CH191-api-key.pem /inheritance:r
	icacls ./NT2205-CH191-api-key.pem /grant:r "$(USERNAME):(F)"
	icacls ./NT2205-CH191-api-key.pem

common:
	sudo tail -n 100 /var/log/cloud-init-output.log | grep -i "error\|failed" -A 10

	cat /tmp/rockspec/apisix-master-0.rockspec

	luarocks list | grep luasec

	/usr/local/apisix/bin/apisix version

	systemctl status apisix

	tail -50 /usr/local/apisix/logs/error.log | grep -A 10 "auth"

	curl -s http://127.0.0.1:9180/apisix/admin/routes/7 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' | jq '.value | {uri, methods, upstream, plugins: .plugins | keys}'

	curl -v -X POST http://127.0.0.1:9080/api/v1/auth/realms/zero-trust/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=test-client&client_secret=test-client-secret&username=testuser&password=testpassword123&grant_type=password"

	curl -v -X POST http://10.0.10.191:8080/realms/zero-trust/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=test-client&client_secret=test-client-secret&username=testuser&password=testpassword123&grant_type=password"

	curl -v -X GET https://extension-app1:8443/call-crm --cert /usr/local/apisix/certs/gateway.crt --key /usr/local/apisix/certs/gateway.key --cacert /usr/local/apisix/certs/ca.crt -H "Authorization: Bearer $ADMIN_TOKEN"
	curl -v -X POST http://127.0.0.1:9080/api/v1/extension-app/call-crm -H "Authorization: Bearer $ADMIN_TOKEN"
	  curl -v -X GET https://extension-app1:8443/call-crm -H "Authorization: Bearer $ADMIN_TOKEN"

	curl -X GET https://52.220.71.23:9443/api/v1/crm/data --cert /app/certs/extension-app1/extension-app1.crt --key /app/certs/extension-app1/extension-app1.key --cacert /app/certs/ca/ca.crt

	openssl x509 -in ./ca.crt -text -noout

	openssl x509 -in ca.crt -noout -issuer
	openssl x509 -in ca.crt -noout -subject
	openssl x509 -in ca.crt -noout -dates

bastion-host:
	aws secretsmanager get-secret-value --secret-id "NT2205-CH191-api/ssh/private-key" --region ap-southeast-1 --query 'SecretString' --output text > api-key.pem
	chmod 600 api-key.pem

