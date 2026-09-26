FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

RUN chmod 0444 /app/server.py /app/requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser

EXPOSE 8000

USER 10001:10001

CMD ["python", "server.py"]
