FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests pysocks cryptography pycryptodome
COPY bot.py run.sh ./
COPY scripts ./scripts
RUN chmod +x run.sh && mkdir -p /sdcard/VPNs
ENV PYTHONUNBUFFERED=1 PORT=8080
EXPOSE 8080
CMD ["./run.sh"]
