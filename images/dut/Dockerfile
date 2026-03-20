FROM python:3.12-alpine
RUN apk add --no-cache bash curl minisign && pip install --no-cache-dir paho-mqtt==2.1.0 requests==2.32.5
WORKDIR /app
COPY dut.py /app/dut.py
ENV PYTHONUNBUFFERED=1
CMD ["python","/app/dut.py"]
