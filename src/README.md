# AAA Server Infrastructure - Zero Trust Authentication

AAA (Authentication, Authorization, Accounting) infrastructure with Keycloak, APISIX API Gateway, and FastAPI services to simulate Zero Trust architecture.

## Architecture

```
Client
  ↓
APISIX API Gateway (Port 9080)
  ↓ (authenticate with)
Keycloak IdP (Port 8080)
  ↓ (forward request to)
Service A (Port 8003)
  ↓ (internal communication)
Service B (Port 8004)
```

## Components

### 1. Keycloak (Identity Provider)
- **Port**: 8080
- **Admin Console**: http://localhost:8080/admin
- **Admin Username**: admin
- **Admin Password**: admin123
- **Realm**: zero-trust
- **Pre-configured Users**:
  - Username: `testuser`, Password: `testpassword123`
  - Username: `admin`, Password: `adminpassword123`
- **Pre-configured Clients**:
  - `test-client`: Client for testing

### 2. APISIX API Gateway
- **Gateway Port**: 9080 (public endpoint)
- **Admin API Port**: 9180
- **Dashboard**: http://localhost:9000
- **Dashboard Credentials**: admin / admin

### 3. Service A (FastAPI)
- **Port**: 8003 (exposed for testing)
- **Endpoints**:
  - `GET /` - Root endpoint
  - `GET /health` - Health check
  - `GET /public` - Public endpoint
  - `GET /protected` - Protected endpoint (requires authentication)
  - `GET /call-b` - Call to Service B

### 4. Service B (FastAPI)
- **Port**: 8004 (exposed for testing, should not be exposed in production)
- **Endpoints**:
  - `GET /` - Root endpoint
  - `GET /health` - Health check
  - `GET /data` - Internal data endpoint

## System Requirements

- Docker Desktop
- Docker Compose
- PowerShell or Bash
- (Optional) curl, jq for testing scripts

## Directory Structure

```
src/
├── docker-compose.yml          # Main Docker Compose configuration
├── dbs.yml                     # Database services configuration
├── keycloak.yml                # Keycloak service configuration
├── services.yml                # Application services configuration
├── apisix/
│   ├── config.yaml             # APISIX Gateway configuration
│   └── dashboard-conf.yaml     # APISIX Dashboard configuration
├── keycloak/
│   └── realm-config.json       # Keycloak realm import config
└── services/
    ├── service-a/
    │   ├── Dockerfile
    │   ├── main.py
    │   └── requirements.txt
    └── service-b/
        ├── Dockerfile
        ├── main.py
        └── requirements.txt

scripts/
├── get-token.ps1               # Script to get JWT token
├── get-token.sh                # Script to get JWT token (Linux/Mac)
├── test-infrastructure.ps1     # Script to test the entire system
└── test-infrastructure.sh      # Script to test the entire system (Linux/Mac)
```

## Next Steps

To implement mTLS for internal communication between services:

1. Create Local CA with OpenSSL (see `/ca` folder)
2. Issue certificates for Service A and Service B
3. Configure FastAPI to require and validate client certificates
4. Update docker-compose to mount certificates into containers

## References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [APISIX Documentation](https://apisix.apache.org/docs/apisix/getting-started/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Propose 4 Documentation](../docs/Propose4.md)
