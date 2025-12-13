FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .

# Expose port
EXPOSE 8001

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--ssl-certfile", "/certs/service-b/service-b.crt", "--ssl-keyfile", "/certs/service-b/service-b.key", "--ssl-ca-certs", "/certs/ca/ca.crt", "--ssl-cert-reqs", "2"]
