import uvicorn
from fastapi import FastAPI, Header, Request, HTTPException, status
from typing import Optional
import os
import ssl
import json
import base64

app = FastAPI(title="Core CRM App")

SERVICE_NAME = os.getenv("SERVICE_NAME", "crm-app")

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
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    x_userinfo: Optional[str] = Header(None, alias="X-Userinfo"),
    x_client_cert_fingerprint: Optional[str] = Header(None, alias="X-Client-Cert-Fingerprint")
):
    """
    Internal endpoint that provides data to Extension Apps.
    Protected by mTLS and Sender Constrained Token Check.
    """
    
    # 1. Enforce mTLS Binding Check
    if not x_client_cert_fingerprint:
        # If upstream (APISIX) didn't send this, it implies mTLS bypass or config error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Client Certificate Fingerprint"
        )

    user_id = x_user_id
    user_roles = []
    jwt_claims = {}
    
    if x_userinfo:
        try:
            decoded_info = base64.b64decode(x_userinfo).decode('utf-8')
            user_info = json.loads(decoded_info)
            user_id = user_info.get("sub", "anonymous")
            user_roles = user_info.get("realm_access", {}).get("roles", [])
            jwt_claims = user_info
            
            print(f"Binding Check: Client Fingerprint={x_client_cert_fingerprint}")

        except Exception as e:
            print(f"Error parsing X-Userinfo: {e}")
            raise HTTPException(status_code=400, detail="Invalid User Info")
            
    return {
        "service": SERVICE_NAME,
        "data": {
            "id": 101,
            "type": "Customer Record",
            "details": "Confidential CRM Data"
        },
        "context_received": {
            "user": user_id,
            "roles": user_roles,
            "fingerprint": x_client_cert_fingerprint
        },
        "message": "Data retrieved successfully via mTLS with Cert Binding"
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
        reload=False
    )
