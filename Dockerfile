FROM python:3.12-slim
WORKDIR /app
COPY bot.py run.sh ./
COPY scripts ./scripts
RUN chmod +x run.sh && mkdir -p /sdcard/VPNs
ENV PYTHONUNBUFFERED=1
CMD ["./run.sh"]
