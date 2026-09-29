FROM python:3.12-slim
WORKDIR /app
COPY dmarc_dashboard ./dmarc_dashboard
VOLUME ["/app/data"]
EXPOSE 8080
# config.ini は -v でマウントする (例: -v $PWD/config.ini:/app/config.ini:ro)
CMD ["python", "-m", "dmarc_dashboard", "serve", "--host", "0.0.0.0", "--fetch-interval", "3600"]
