FROM python:3.11-slim
WORKDIR /app
COPY requirements-observer.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY EXERSISE-2/lab_02_failover_observer.py ./observer.py
CMD ["python", "-u", "observer.py"]
