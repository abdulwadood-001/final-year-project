# HoneyBot-IoT — Module 8 ML inference microservice (ml_api)
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd -m -u 10003 mluser && mkdir -p /app/ml/artifacts && chown -R mluser /app
WORKDIR /app
COPY requirements-base.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements-ml.txt
COPY common/ ./common/
COPY ml/ ./ml/
USER mluser
EXPOSE 5001
# trains a synthetic baseline on first boot if no model is mounted, then serves it
CMD ["python", "-m", "ml.ml_api"]
