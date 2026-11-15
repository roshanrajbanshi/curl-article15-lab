FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# self-signed cert for HTTPS testing (CN=flask-app.lab)
RUN openssl req -x509 -newkey rsa:2048 -keyout /app/key.pem -out /app/cert.pem \
    -days 365 -nodes -subj "/CN=flask-app.lab"

EXPOSE 5000 5443

CMD ["sh", "-c", "python app.py & gunicorn -b 0.0.0.0:5443 --certfile=/app/cert.pem --keyfile=/app/key.pem app:app"]
