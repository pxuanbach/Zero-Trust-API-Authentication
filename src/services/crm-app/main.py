import uvicorn
from fastapi import FastAPI, HTTPException, Header, Request
from typing import Optional
import os
import ssl
import json
import base64

app = FastAPI(title="Core CRM App")

SERVICE_NAME = os.getenv("SERVICE_NAME", "crm-app")

# Paths to certificates
SERVER_CERT = os.getenv("SERVER_CERT", "/app/certs/crm-app/service-b.crt")
SERVER_KEY = os.getenv("SERVER_KEY", "/app/certs/crm-app/service-b.key")
CA_CERT = os.getenv("CA_CERT", "/app/certs/ca/ca.crt")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": SERVICE_NAME,
        "message": "Hello from Core CRM App",
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": SERVICE_NAME}

@app.get("/data")
async def get_data(
    request: Request,
    x_source_service: Optional[str] = Header(None, alias="X-Source-Service"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    x_userinfo: Optional[str] = Header(None, alias="X-Userinfo")
):
    """
    Internal endpoint that provides data to Extension Apps.
    Protected by mTLS.
    """
    
    user_id = x_user_id
    user_roles = []
    
    # If called directly from Gateway, parse X-Userinfo
    if x_userinfo:
        try:
            decoded_info = base64.b64decode(x_userinfo).decode('utf-8')
            user_info = json.loads(decoded_info)
            user_id = user_info.get("sub", "anonymous")
            user_roles = user_info.get("realm_access", {}).get("roles", [])
        except Exception as e:
            print(f"Error parsing X-Userinfo: {e}")
            
    return {
        "service": SERVICE_NAME,
        "data": {
            "id": 101,
            "type": "Customer Record",
            "details": "Confidential CRM Data"
        },
        "context_received": {
            "source": x_source_service if x_source_service else "gateway",
            "user": user_id,
            "roles": user_roles
        },
        "message": "Data retrieved successfully via mTLS"
    }

@app.delete("/data/{record_id}")
async def delete_data(record_id: int):
    """
    Endpoint to simulate data deletion.
    Only accessible by Admin (enforced by Gateway).
    """
    return {
        "message": f"Record {record_id} deleted successfully",
        "status": "deleted"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        ssl_keyfile=SERVER_KEY,
        ssl_certfile=SERVER_CERT,
        ssl_ca_certs=CA_CERT,
        ssl_cert_reqs=ssl.CERT_REQUIRED, # Force Client Auth
        reload=True
    )
