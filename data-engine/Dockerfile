FROM python:3.11-slim

WORKDIR /app

# Copy requirements from data-engine
COPY data-engine/requirement.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy generator from data-engine
COPY data-engine/generator.py .

EXPOSE 8000

CMD ["python", "generator.py"]