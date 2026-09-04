FROM python:3.11-slim
WORKDIR /app
COPY target_demo/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY target_demo/app.py .
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
