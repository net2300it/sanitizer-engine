FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY yara_scanner.py .
COPY sanitizer_integration.py .
COPY sanitizer_api.py .
COPY example_rules.yar ./rules/example_rules.yar

# Create necessary directories
RUN mkdir -p /app/rules /app/quarantine /app/logs

# Set environment variables
ENV YARA_RULES_PATH=/app/rules
ENV QUARANTINE_DIR=/app/quarantine
ENV SCAN_TIMEOUT=60
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')"

# Run the API server
CMD ["python", "sanitizer_api.py", "--host", "0.0.0.0", "--port", "5000"]
