FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc cmake make libssl-dev libbluetooth-dev libwebsockets-dev libcjson-dev libtss2-dev libpam0g-dev pamtester \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /artifact
COPY . .
RUN ./build_pam.sh
CMD ["ctest", "--test-dir", "build", "--output-on-failure"]
