FROM python:3.12-alpine
RUN pip install --no-cache-dir python-dateutil matplotlib
ENV MPLBACKEND=Agg
WORKDIR /app
COPY collector.py /app/collector.py
COPY analyze_results.py /app/analyze_results.py
CMD ["python","/app/collector.py"]
