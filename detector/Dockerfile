FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -s /bin/false appuser
USER appuser

RUN mkdir -p /var/log/detector

CMD ["python", "main.py"]