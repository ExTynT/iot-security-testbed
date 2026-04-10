FROM python:3.12-alpine
RUN apk add --no-cache bash curl minisign && \
    pip install --no-cache-dir paho-mqtt==2.1.0 requests==2.32.5 && \
    addgroup -S app -g 10001 && \
    adduser -S -G app -u 10001 app
WORKDIR /app
COPY dut.py /app/dut.py
RUN chown -R app:app /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER app
CMD ["python","/app/dut.py"]
