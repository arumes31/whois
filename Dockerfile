# syntax=docker/dockerfile:1.6
FROM python:3.13-slim-bookworm

# --- System packages (only what we still need) ---
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # For background image download
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Python dependencies ---
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# --- App code ---
COPY . /app
RUN mkdir -p /app/static

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "--threads", "2", "-b", "0.0.0.0:5000", "app:app"]