FROM python:3.12-alpine
RUN pip install --no-cache-dir python-dateutil
WORKDIR /app
COPY collector.py /app/collector.py
CMD ["python","/app/collector.py"]
