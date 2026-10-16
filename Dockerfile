FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY crtwatch ./crtwatch
RUN pip install --no-cache-dir .
ENV CRTWATCH_DB=/data/crtwatch.db PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8080
# Dashboard + background rescans every 6 hours. Requires CRTWATCH_PASSWORD (see docker-compose.yml).
CMD ["crtwatch", "serve", "--host", "0.0.0.0", "--port", "8080", "--every", "6h"]
