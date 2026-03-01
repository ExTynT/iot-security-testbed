FROM python:3.12-alpine
RUN apk add --no-cache bash curl minisign && pip install --no-cache-dir paho-mqtt requests
WORKDIR /app
COPY dut.py /app/dut.py
ENV PYTHONUNBUFFERED=1
CMD ["python","/app/dut.py"]
