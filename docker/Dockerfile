FROM python:3.11-slim

LABEL maintainer="RansomEmu Team"
LABEL description="Ransomware emulation framework for Purple/Red Team testing"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ransomemu

# Install Python deps first (cache layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e "." 2>/dev/null || true

# Copy source
COPY . .

# Install package
RUN pip install --no-cache-dir -e .

# Copy configurations and templates
COPY config/ config/
COPY templates/ templates/

# Default command
ENTRYPOINT ["ransomemu"]
CMD ["--help"]
