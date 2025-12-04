from fastapi import FastAPI, HTTPException
import os

app = FastAPI(title="Service B")

SERVICE_NAME = os.getenv("SERVICE_NAME", "service-b")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": SERVICE_NAME,
        "message": "Hello from Service B",
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": SERVICE_NAME}

@app.get("/data")
async def get_data():
    """
    Internal endpoint that provides data to other services
    In production, this would be protected by mTLS
    """
    return {
        "service": SERVICE_NAME,
        "data": {
            "id": 12345,
            "name": "Sample Data from Service B",
            "description": "This data is retrieved from an internal service",
            "items": ["item1", "item2", "item3"]
        },
        "message": "Data retrieved successfully"
    }

@app.post("/process")
async def process_data(payload: dict):
    """Internal endpoint for data processing"""
    return {
        "service": SERVICE_NAME,
        "message": "Data processed successfully",
        "received_payload": payload,
        "result": "processed"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
