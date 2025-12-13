from fastapi import FastAPI, HTTPException, Header, Depends
from typing import Optional, Dict, Any
from jose import jwt, JWTError
import httpx
import os

app = FastAPI(title="Service A")

SERVICE_NAME = os.getenv("SERVICE_NAME", "service-a")
SERVICE_B_URL = os.getenv("SERVICE_B_URL", "https://service-b:8001")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.getenv("REALM", "zero-trust")

# Global cache for JWKS removed as we are using Gateway Offloading

async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Get user info from the JWT token.
    
    Security Warning: Ensure this service is only accessible from the Gateway (e.g., via mTLS or Network Policies).
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authentication scheme")

    token = authorization.split(" ")[1]
    
    try:
        # Decode token without verifying signature
        payload = jwt.decode(
            token,
            key="", # Key is not needed when verify_signature is False
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False
            }
        )
        
        return payload
        
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token format: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")

@app.get("/")
async def root():
    """Public endpoint"""
    return {
        "service": SERVICE_NAME,
        "message": "Hello from Service A",
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": SERVICE_NAME}

@app.get("/public")
async def public_endpoint():
    """Public endpoint accessible through Gateway"""
    return {
        "service": SERVICE_NAME,
        "endpoint": "public",
        "message": "This is a public endpoint"
    }

@app.get("/call-b")
async def call_service_b(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Protected endpoint that calls Service B
    This demonstrates internal service-to-service communication
    """
    try:
        async with httpx.AsyncClient(
                verify="/certs/ca/ca.crt",
                cert=(
                    "/certs/service-a/service-a.crt",
                    "/certs/service-a/service-a.key"
                )
            ) as client:
            response = await client.get(
                f"{SERVICE_B_URL}/data",
                timeout=10.0
            )
            response.raise_for_status()
            service_b_data = response.json()
        
        return {
            "service": SERVICE_NAME,
            "message": "Successfully called Service B",
            "data_from_service_b": service_b_data,
            "user": user.get("preferred_username")
        }
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to communicate with Service B: {str(e)}"
        )

@app.get("/protected")
async def protected_endpoint(user: Dict[str, Any] = Depends(get_current_user)):
    """Protected endpoint that requires authentication"""
    return {
        "service": SERVICE_NAME,
        "endpoint": "protected",
        "message": "You have successfully accessed a protected endpoint",
        "user": user.get("preferred_username"),
        "auth_header_present": True
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
