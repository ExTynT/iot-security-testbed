FROM python:3.12-alpine
RUN pip install --no-cache-dir python-dateutil==2.9.0.post0 matplotlib==3.10.8 && \
    addgroup -S collector -g 10003 && \
    adduser -S -G collector -u 10003 collector
ENV MPLBACKEND=Agg \
    MPLCONFIGDIR=/tmp/matplotlib \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY collector.py /app/collector.py
COPY analyze_results.py /app/analyze_results.py
RUN chown -R collector:collector /app
USER collector
CMD ["python","/app/collector.py"]
