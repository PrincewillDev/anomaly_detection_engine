FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -s /bin/false appuser && \
    mkdir -p /var/log/detection && \
    chown appuser /var/log/detection

USER appuser

CMD ["python", "main.py"]