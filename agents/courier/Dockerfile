FROM python:3.12-slim
WORKDIR /app
COPY agents/shared/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY agents/shared /app/shared
COPY agents/courier /app
CMD ["python", "-u", "agent.py"]
