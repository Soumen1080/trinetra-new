FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project specification
COPY pyproject.toml .

# Install dependencies and the package in editable/local mode
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . && \
    pip install --no-cache-dir openpyxl

# Copy application source code
COPY app ./app
COPY alembic.ini .
COPY alembic ./alembic
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Create data directory for SQLite & reports
RUN mkdir -p /data/reports && \
    chmod +x /docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1
ENV TRINETRA_DATABASE_URL="sqlite:////data/trinetra.db"
ENV TRINETRA_REPORT_STORE="/data/reports"
ENV TRINETRA_AUTO_CREATE_SCHEMA="false"

EXPOSE 8000

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
