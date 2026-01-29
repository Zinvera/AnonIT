FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory
RUN mkdir -p /app/data

# Non-root user for security
RUN useradd -m -u 1000 anonit && chown -R anonit:anonit /app
USER anonit

# Expose port
EXPOSE 8765

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8765)); s.close()"

# Run server
CMD ["python", "server.py"]
