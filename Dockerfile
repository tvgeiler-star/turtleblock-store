FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/tvgeiler-star/geiler-store"
LABEL org.opencontainers.image.description="TurtleBlock Home - DNS-Filter mit Adblocker-Pro-DNA"
WORKDIR /app
COPY app/server.py app/index.html ./
COPY app/lists/ ./lists/
EXPOSE 8196
CMD ["python3", "/app/server.py"]
