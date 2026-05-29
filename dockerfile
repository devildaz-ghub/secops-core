# Use official Python lightweight image
FROM python:3.10-slim

# Install system dependencies required for Scapy and Nmap
RUN apt-get update && apt-get install -y \
    nmap \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency list and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY server.py .
COPY index.html .

# Expose the dashboard port
EXPOSE 13000

# Start the FastAPI server
CMD ["python", "server.py"]