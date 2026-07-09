FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y python3 python3-pip python3.11-venv nmap