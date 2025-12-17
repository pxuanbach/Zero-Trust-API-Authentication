#!/bin/bash
set -e

# Update system
sudo yum update -y
sudo yum install -y git curl wget gcc pcre-devel openssl-devel zlib-devel python3 python3-pip unzip make lua lua-devel openldap-devel

# Update /etc/hosts for mTLS hostname verification
echo "${extension_app_private_ip} extension-app1" | sudo tee -a /etc/hosts
echo "${crm_app_private_ip} crm-app" | sudo tee -a /etc/hosts
echo "127.0.0.1 apisix" | sudo tee -a /etc/hosts

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf aws awscliv2.zip

# Install OpenResty (APISIX dependency)
# wget https://openresty.org/package/centos/openresty.repo -O /etc/yum.repos.d/openresty.repo
# sudo sed -i 's/$releasever/7/g' /etc/yum.repos.d/openresty.repo
# sudo yum install -y openresty openresty-resty openresty-openssl-devel

# Install etcd (APISIX configuration store)
ETCD_VERSION=v3.5.9
sudo wget https://github.com/etcd-io/etcd/releases/download/$ETCD_VERSION/etcd-$ETCD_VERSION-linux-amd64.tar.gz
sudo tar -xzf etcd-$ETCD_VERSION-linux-amd64.tar.gz
sudo mv etcd-$ETCD_VERSION-linux-amd64/etcd* /usr/local/bin/
sudo rm -rf etcd-$ETCD_VERSION-linux-amd64*

# Create etcd systemd service
sudo cat > /etc/systemd/system/etcd.service << 'EOFETCD'
[Unit]
Description=etcd key-value store
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/etcd --listen-client-urls http://127.0.0.1:2379 --advertise-client-urls http://127.0.0.1:2379
Restart=always
RestartSec=10s
LimitNOFILE=40000

[Install]
WantedBy=multi-user.target
EOFETCD

systemctl daemon-reload
systemctl enable etcd
systemctl start etcd

# Wait for etcd
sleep 5

# Install APISIX from RPM
sudo yum install -y https://repos.apiseven.com/packages/centos/apache-apisix-repo-1.0-1.noarch.rpm
sudo yum-config-manager --add-repo https://repos.apiseven.com/packages/centos/apache-apisix.repo
sudo sed -i 's/$releasever/7/g' /etc/yum.repos.d/apache-apisix.repo
sudo sed -i 's/$releasever/7/g' /etc/yum.repos.d/openresty.repo
sudo yum install -y apisix

# Create necessary directories
sudo mkdir -p /usr/local/apisix/{conf,logs,certs}

aws secretsmanager get-secret-value --secret-id ${project_name}/gateway/cert --region ${aws_region} \
  --query SecretString --output text 2>/dev/null | sudo tee /usr/local/apisix/certs/gateway.crt > /dev/null

aws secretsmanager get-secret-value --secret-id ${project_name}/gateway/key --region ${aws_region} \
  --query SecretString --output text 2>/dev/null | sudo tee /usr/local/apisix/certs/gateway.key > /dev/null

aws secretsmanager get-secret-value --secret-id ${project_name}/ca/cert --region ${aws_region} \
  --query SecretString --output text 2>/dev/null | sudo tee /usr/local/apisix/certs/ca.crt > /dev/null

sudo chmod 600 /usr/local/apisix/certs/*

# Clone repo to get config files
# mkdir -p /opt/apisix-config
# cd /opt/apisix-config
# git clone https://github.com/pxuanbach/Zero-Trust-API-Authentication.git repo

# Create APISIX configuration
cat > /usr/local/apisix/conf/config.yaml << EOFCONFIG
apisix:
  node_listen: 9080
  enable_ipv6: false

deployment:
  role: traditional
  role_traditional:
    config_provider: etcd
  admin:
    admin_key:
      - name: admin
        key: ${apisix_admin_key}
        role: admin

  etcd:
    host:
      - http://127.0.0.1:2379
    prefix: /apisix
    timeout: 30

nginx_config:
  error_log: "/usr/local/apisix/logs/error.log"
  error_log_level: "warn"
  http:
    access_log: "/usr/local/apisix/logs/access.log"
    access_log_format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_response_time "$http_authorization"'

plugins:
  - cors
  - limit-req
  - openid-connect
  - authz-keycloak
  - proxy-rewrite
  - request-id
  - fault-injection
  - http-logger
  
ssl:
  enable: false
  # listen:
  #   - port: 9443
  # ssl_protocols: "TLSv1.2 TLSv1.3"
  # ssl_ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
EOFCONFIG

# Enable and start APISIX
systemctl daemon-reload
systemctl enable apisix
systemctl start apisix

# Install jq for JSON processing
wget -O /usr/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
chmod +x /usr/bin/jq

# Wait for APISIX to start
echo "Waiting for APISIX to start..."
until curl -s http://127.0.0.1:9180/apisix/admin/routes > /dev/null; do
  sleep 2
  echo "Waiting for APISIX..."
done
echo "APISIX is up."

# Read certs
CERT_CONTENT=$(cat /usr/local/apisix/certs/gateway.crt)
KEY_CONTENT=$(cat /usr/local/apisix/certs/gateway.key)
CA_CONTENT=$(cat /usr/local/apisix/certs/ca.crt)

# Common Plugins JSON
COMMON_PLUGINS=$(/usr/bin/jq -n '{
  "cors": {
    "allow_origins": "*",
    "allow_methods": "*",
    "allow_headers": "*"
  },
  "request-id": {
    "include_in_response": true
  },
  "openid-connect": {
    "client_id": "test-client",
    "client_secret": "test-client-secret",
    "discovery": "http://'${alb_dns_name}'/api/v1/auth/realms/zero-trust/.well-known/openid-configuration",
    "bearer_only": true,
    "realm": "zero-trust",
    "token_signing_alg_values_expected": "RS256"
  },
  "limit-req": {
    "rate": 10,
    "burst": 5,
    "key": "consumer_name",
    "rejected_code": 429
  }
}')

# Route 1: Extension App
curl http://127.0.0.1:9180/apisix/admin/routes/1 \
  -H 'X-API-KEY: ${apisix_admin_key}' \
  -X PUT -d "$(/usr/bin/jq -n \
    --argjson plugins "$COMMON_PLUGINS" \
    --arg cert "$CERT_CONTENT" \
    --arg key "$KEY_CONTENT" \
    --arg ca "$CA_CONTENT" \
    '{
      "uri": "/api/v1/extension-app/*",
      "name": "extension-app-route",
      "methods": ["GET", "POST", "PUT"],
      "plugins": ($plugins + {
        "proxy-rewrite": {
          "regex_uri": ["^/api/v1/extension-app/(.*)", "/$1"]
        }
      }),
      "upstream": {
        "nodes": {
          "extension-app1:8443": 1
        },
        "type": "roundrobin",
        "scheme": "https",
        "tls": {
          "client_cert": $cert,
          "client_key": $key,
          "ca_cert": $ca,
          "verify": true
        }
      }
    }')"

# Route 2: Extension App Admin
curl http://127.0.0.1:9180/apisix/admin/routes/2 \
  -H 'X-API-KEY: ${apisix_admin_key}' \
  -X PUT -d "$(/usr/bin/jq -n \
    --argjson plugins "$COMMON_PLUGINS" \
    --arg cert "$CERT_CONTENT" \
    --arg key "$KEY_CONTENT" \
    --arg ca "$CA_CONTENT" \
    '{
      "uri": "/api/v1/extension-app/*",
      "name": "extension-app-route-admin",
      "methods": ["DELETE"],
      "plugins": ($plugins + {
        "proxy-rewrite": {
          "regex_uri": ["^/api/v1/extension-app/(.*)", "/$1"]
        },
        "authz-keycloak": {
          "token_endpoint": "http://'${alb_dns_name}'/api/v1/auth/realms/zero-trust/protocol/openid-connect/token",
          "client_id": "test-client",
          "client_secret": "test-client-secret",
          "policy_enforcement_mode": "ENFORCING",
          "permissions": ["Extension App Delete Resource"]
        }
      }),
      "upstream": {
        "nodes": {
          "extension-app1:8443": 1
        },
        "type": "roundrobin",
        "scheme": "https",
        "tls": {
          "client_cert": $cert,
          "client_key": $key,
          "ca_cert": $ca,
          "verify": true
        }
      }
    }')"

# Route 3: CRM App
curl http://127.0.0.1:9180/apisix/admin/routes/3 \
  -H 'X-API-KEY: ${apisix_admin_key}' \
  -X PUT -d "$(/usr/bin/jq -n \
    --argjson plugins "$COMMON_PLUGINS" \
    --arg cert "$CERT_CONTENT" \
    --arg key "$KEY_CONTENT" \
    --arg ca "$CA_CONTENT" \
    '{
      "uri": "/api/v1/crm/*",
      "name": "crm-app-route",
      "methods": ["GET", "POST", "PUT"],
      "plugins": ($plugins + {
        "proxy-rewrite": {
          "regex_uri": ["^/api/v1/crm/(.*)", "/$1"]
        }
      }),
      "upstream": {
        "nodes": {
          "crm-app:8443": 1
        },
        "type": "roundrobin",
        "scheme": "https",
        "tls": {
          "client_cert": $cert,
          "client_key": $key,
          "ca_cert": $ca,
          "verify": true
        }
      }
    }')"

# Route 4: CRM App Admin
curl http://127.0.0.1:9180/apisix/admin/routes/4 \
  -H 'X-API-KEY: ${apisix_admin_key}' \
  -X PUT -d "$(/usr/bin/jq -n \
    --argjson plugins "$COMMON_PLUGINS" \
    --arg cert "$CERT_CONTENT" \
    --arg key "$KEY_CONTENT" \
    --arg ca "$CA_CONTENT" \
    '{
      "uri": "/api/v1/crm/*",
      "name": "crm-app-route-admin",
      "methods": ["DELETE"],
      "plugins": ($plugins + {
        "proxy-rewrite": {
          "regex_uri": ["^/api/v1/crm/(.*)", "/$1"]
        },
        "authz-keycloak": {
          "token_endpoint": "http://'${alb_dns_name}'/api/v1/auth/realms/zero-trust/protocol/openid-connect/token",
          "client_id": "test-client",
          "client_secret": "test-client-secret",
          "policy_enforcement_mode": "ENFORCING",
          "permissions": ["CRM App Delete Resource"]
        }
      }),
      "upstream": {
        "nodes": {
          "crm-app:8443": 1
        },
        "type": "roundrobin",
        "scheme": "https",
        "tls": {
          "client_cert": $cert,
          "client_key": $key,
          "ca_cert": $ca,
          "verify": true
        }
      }
    }')"

# Route 5: Auth Route (Keycloak)
curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/5 \
  -H 'X-API-KEY: ${apisix_admin_key}' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "auth-route",
    "methods": ["POST", "GET"],
    "uri": "/api/v1/auth/*",
    "plugins": {
      "cors": {
        "allow_origins": "*",
        "expose_headers": "*",
        "allow_methods": "*",
        "allow_credential": false,
        "max_age": 5,
        "allow_headers": "*"
      },
      "proxy-rewrite": {
        "regex_uri": ["^/api/v1/auth/(.*)", "/$1"]
      }
    },
    "upstream": {
      "nodes": {
        "'${keycloak_private_ip}':8080": 1
      },
      "type": "roundrobin",
      "scheme": "http",
      "pass_host": "pass",
      "timeout": {
        "connect": 30,
        "read": 30,
        "send": 30
      }
    }
  }'

sleep 1

# Route 6: Health Check Status
curl http://127.0.0.1:9180/apisix/admin/routes/6 \
  -H 'X-API-KEY: ${apisix_admin_key}' \
  -X PUT -d "$(/usr/bin/jq -n \
    '{
      "uri": "/apisix/status",
      "name": "health-check-route",
      "methods": ["GET"],
      "plugins": {
        "fault-injection": {
          "abort": {
            "http_status": 200,
            "body": "{\"status\": \"UP\", \"timestamp\": \"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'\", \"service\": \"APISIX\", \"version\": \"3.7.0\"}"
          }
        }
      },
      "upstream": {
        "nodes": {
          "127.0.0.1:9080": 1
        },
        "type": "roundrobin"
      }
    }')"

# Route 7: Keycloak Direct (for OIDC plugin callbacks and introspection)
curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/7 \
  -H 'X-API-KEY: ${apisix_admin_key}' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "keycloak-direct-route",
    "methods": ["POST", "GET", "PUT", "DELETE"],
    "uris": ["/realms/*", "/resources/*", "/js/*", "/robots.txt"],
    "upstream": {
      "nodes": {
        "'${keycloak_private_ip}':8080": 1
      },
      "type": "roundrobin",
      "scheme": "http",
      "pass_host": "pass",
      "timeout": {
        "connect": 30,
        "read": 30,
        "send": 30
      }
    }
  }'

# Log startup
echo "APISIX started at $(date)" >> /var/log/apisix-startup.log
