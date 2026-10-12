FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py analysis.py zeek_monitor.py ./
COPY sample_data ./sample_data
EXPOSE 5000
CMD ["python", "app.py"]
