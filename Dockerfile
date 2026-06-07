# Native arm64 on Apple Silicon (M-series); also works on amd64.
FROM python:3.12-slim

WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (node.py, adversary.py, client.py, crypto_utils.py)
COPY src/ ./
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENV MODE=pbft
ENTRYPOINT ["./entrypoint.sh"]
