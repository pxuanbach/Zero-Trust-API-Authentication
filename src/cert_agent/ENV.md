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
| `CERT_AGENT_CERTIFICATE_ALGORITHM` | `ECDSA_P256` | Certificate generation algorithm: `ECDSA_P256`, `RSA_2048`, `ED25519` |
| `CERT_AGENT_TOKEN_ALGORITHM` | `ES256` | Token signing algorithm: `ES256`, `RS256`, `EdDSA` |
| `CERT_AGENT_HASH_ALGORITHM` | `SHA256` | Hash algorithm: `SHA256`, `SHA512`, `SHA3_256`, `SHA3_512` |
| `CERT_AGENT_RSA_KEY_SIZE` | `2048` | RSA key size: `2048`, `4096` (only for RSA_2048) |
| `CERT_AGENT_CERTIFICATE_VALIDITY_DAYS` | `90` | Certificate validity period in days |
| `CERT_AGENT_AWS_REGION` | `None` | AWS region for ACM (for aws adapter) |
| `CERT_AGENT_AWS_ACCESS_KEY_ID` | `None` | AWS access key ID (for aws adapter) |
| `CERT_AGENT_AWS_SECRET_ACCESS_KEY` | `None` | AWS secret access key (for aws adapter) |
| `CERT_AGENT_CORS_ORIGINS` | `*` | Comma-separated list of allowed CORS origins |
| `CERT_AGENT_CORS_ALLOW_CREDENTIALS` | `true` | Allow credentials in CORS requests |
