FROM debian:bookworm-slim

ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    tesseract-ocr poppler-utils \
    libgl1-mesa-glx libglib2.0-0 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

# FIX: allow pip installation in Debian managed environment
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
