# Certificate Agent Environment Variables

All variables use the prefix `CERT_AGENT_` when set as environment variables.

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_AGENT_CERT_ADAPTER` | `internal` | Certificate adapter type: `internal`, `aws`, or `letsencrypt` |
| `CERT_AGENT_HOST` | `0.0.0.0` | Host to bind the server to |
| `CERT_AGENT_PORT` | `8080` | Port to bind the server to |
| `CERT_AGENT_LOG_LEVEL` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `CERT_AGENT_CA_CERT_PATH` | `ca/ca.crt` | Path to CA certificate file (for internal adapter) |
| `CERT_AGENT_CA_KEY_PATH` | `ca/ca.key` | Path to CA private key file (for internal adapter) |
| `CERT_AGENT_CERT_STORAGE_PATH` | `certs/` | Directory to store issued certificates (for internal adapter) |
| `CERT_AGENT_AWS_REGION` | `None` | AWS region for ACM (for aws adapter) |
| `CERT_AGENT_AWS_ACCESS_KEY_ID` | `None` | AWS access key ID (for aws adapter) |
| `CERT_AGENT_AWS_SECRET_ACCESS_KEY` | `None` | AWS secret access key (for aws adapter) |
| `CERT_AGENT_CORS_ORIGINS` | `*` | Comma-separated list of allowed CORS origins |
| `CERT_AGENT_CORS_ALLOW_CREDENTIALS` | `true` | Allow credentials in CORS requests |
