import uvicorn
from fastapi import FastAPI, HTTPException, Header, Request
from typing import Optional
import httpx
import os
import ssl
import json
import base64

app = FastAPI(title="Extension App 1")

SERVICE_NAME = os.getenv("SERVICE_NAME", "extension-app1")
CRM_APP_URL = os.getenv("CRM_APP_URL", "https://crm-app:8001")

# Paths to certificates
SERVER_CERT = os.getenv("SERVER_CERT", "/app/certs/extension-app1/service-a.crt")
SERVER_KEY = os.getenv("SERVER_KEY", "/app/certs/extension-app1/service-a.key")
CA_CERT = os.getenv("CA_CERT", "/app/certs/ca/ca.crt")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": SERVICE_NAME,
        "message": "Hello from Extension App 1",
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": SERVICE_NAME}

@app.get("/call-crm")
async def call_crm(
    request: Request,
    x_userinfo: Optional[str] = Header(None, alias="X-Userinfo")
):
    """
    Endpoint to call Core CRM App using mTLS.
    It propagates User Context received from Gateway (via X-Userinfo).
    """
    
    user_id = "anonymous"
    user_roles = []
    
    if x_userinfo:
        try:
            # Decode Base64 X-Userinfo header from APISIX
            decoded_info = base64.b64decode(x_userinfo).decode('utf-8')
            user_info = json.loads(decoded_info)
            user_id = user_info.get("sub", "anonymous")
            user_roles = user_info.get("realm_access", {}).get("roles", [])
        except Exception as e:
            print(f"Error parsing X-Userinfo: {e}")

    headers = {
        "X-Source-Service": SERVICE_NAME,
        "X-User-ID": user_id
    }

    try:
        # httpx handles loading the certs and verifying the CA automatically
        async with httpx.AsyncClient(verify=CA_CERT, cert=(SERVER_CERT, SERVER_KEY)) as client:
            response = await client.get(
                f"{CRM_APP_URL}/data",
                headers=headers
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"CRM App returned error: {response.text}"
                )
                
            return {
                "message": "Successfully called CRM App",
                "crm_response": response.json(),
                "user_context": {
                    "user_id": user_id,
                    "roles": user_roles
                }
            }
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Failed to connect to CRM App: {str(e)}")
    except ssl.SSLError as e:
        raise HTTPException(status_code=403, detail=f"mTLS Handshake Failed: {str(e)}")

@app.delete("/resource/{resource_id}")
async def delete_resource(resource_id: int):
    """
    Endpoint to simulate resource deletion.
    Only accessible by Admin (enforced by Gateway).
    """
    return {
        "message": f"Resource {resource_id} deleted successfully",
        "status": "deleted"
    }

if __name__ == "__main__":
    # Run as HTTPS Server (mTLS Server)
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile=SERVER_KEY,
        ssl_certfile=SERVER_CERT,
        ssl_ca_certs=CA_CERT,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        reload=True
    )
