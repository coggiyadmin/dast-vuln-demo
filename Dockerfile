FROM python:3.12-slim
WORKDIR /app
COPY app.py safe_app.py ./
RUN pip install --no-cache-dir flask==3.0.0
EXPOSE 8080
CMD ["python", "app.py"]
