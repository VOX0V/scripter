FROM python:3.11-slim

RUN groupadd -g 1000 scripter \
    && useradd -u 1000 -g scripter -m -s /usr/sbin/nologin scripter

WORKDIR /usr/src/app

COPY requirements.txt .
COPY VERSION .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY app ./app
COPY wsgi.py .

RUN mkdir -p /usr/src/app/instance /usr/src/app/data/logs \
    && chown -R scripter:scripter /usr/src/app \
    && chmod 700 /usr/src/app/instance /usr/src/app/data

USER scripter

EXPOSE 8000

CMD ["gunicorn", "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "--workers", "1", "--bind", "0.0.0.0:8000", "wsgi:app"]
