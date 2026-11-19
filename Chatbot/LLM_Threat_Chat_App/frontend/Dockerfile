FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir streamlit requests pandas
COPY chat_app.py .
EXPOSE 8501
CMD ["streamlit", "run", "chat_app.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
