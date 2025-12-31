FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && curl -LO https://github.com/smallstep/cli/releases/download/v0.24.4/step-cli_0.24.4_amd64.deb \
    && dpkg -i step-cli_0.24.4_amd64.deb \
    && rm step-cli_0.24.4_amd64.deb \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
RUN pip install --no-cache-dir requests

# These will be copied from the context (see apisix.yml build context)
COPY ./apisix/init_routes.py /app/init_routes.py

# Run directly without entrypoint script
CMD ["sh", "-c", "python /app/init_routes.py"]
