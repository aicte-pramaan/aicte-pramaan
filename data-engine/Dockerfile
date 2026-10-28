
FROM python:3.11-slim

WORKDIR /app

COPY requirement.txt .
RUN pip install --no-cache-dir -r requirement.txt

COPY generator.py .

EXPOSE 10000

CMD ["sh", "-c", "uvicorn generator:app --host 0.0.0.0 --port ${PORT:-10000}"]
