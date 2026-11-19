FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin appuser
COPY requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app.py scheduler.py ./
RUN mkdir -p /app/logs && chown -R appuser:appuser /app
USER appuser

EXPOSE 8501

# Health checks are configured per service in docker-compose.yml because this
# image runs both Streamlit (dashboard) and the scheduler (worker).
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
