import uvicorn
from fastapi import FastAPI, Header, Request, HTTPException
from typing import Optional
import httpx
import os
import json
import base64
import ssl

app = FastAPI(title="Extension App 1")

SERVICE_NAME = os.getenv("SERVICE_NAME", "extension-app1")
GATEWAY_URL = os.getenv("CRM_APP_URL", "https://apisix:9443/api/v1/crm")


# Paths to certificates
SERVER_CERT = os.getenv("SERVER_CERT", f"/app/certs/{SERVICE_NAME}/{SERVICE_NAME}.crt")
SERVER_KEY = os.getenv("SERVER_KEY", f"/app/certs/{SERVICE_NAME}/{SERVICE_NAME}.key")
CA_CERT = os.getenv("CA_CERT", "/app/certs/ca/ca.crt")
USE_MTLS = os.getenv("USE_MTLS", "true").lower() == "true"


@app.get("/")
async def root():
    return {
        "service": SERVICE_NAME,
        "message": "Hello from Extension App 1",
        "status": "running",
        "mtls_enabled": USE_MTLS
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": SERVICE_NAME}


@app.get("/call-crm")
async def call_crm(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Endpoint to call APISIX Gateway using mTLS.
    APISIX will forward the valid request to CRM App.
    """
    headers = {"X-Source-Service": SERVICE_NAME}
    if authorization:
        headers["Authorization"] = authorization
    else:
        raise HTTPException(status_code=401, detail="Authorization header is required")

    try:
        # Determine SSL context based on configuration
        if USE_MTLS:
            # Create SSL context with fresh cert files
            ssl_context = ssl.create_default_context(cafile=CA_CERT)
            ssl_context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            verify_param = ssl_context
        else:
            # Disable verification if mTLS is not used (simulating app without certs)
            verify_param = False

        async with httpx.AsyncClient(
            verify=verify_param,
            timeout=30.0
        ) as client:
            response = await client.get(
                f"{GATEWAY_URL}/data",
                headers=headers
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"CRM App returned error: {response.text}"
                )
                
            return {
                "message": "Successfully called CRM App",
                "crm_response": response.json()
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
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
