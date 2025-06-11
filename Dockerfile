FROM rust:1.76 as builder
WORKDIR /app

RUN apt-get update && apt-get install -y \
    musl-tools \
    libudev-dev \
    libusb-1.0-0-dev \
    pkg-config \
    libx11-dev \
    libglib2.0-dev \
    libgtk-3-dev \
    libjavascriptcoregtk-4.1-dev \
    libsoup-3.0-dev \
    libwebkit2gtk-4.1-dev \
    protobuf-compiler \
    cmake \
    tor

COPY . .
WORKDIR /app/applications/minotari_console_wallet

RUN cargo build --release 


FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates tor && rm -rf /var/lib/apt/lists/*
COPY --from=builder app/target/release/minotari_console_wallet /usr/local/bin/minotari_console_wallet

COPY config.toml /usr/local/bin/wallet_data/config.toml

# Default command (can be overridden)
ENTRYPOINT ["/usr/local/bin/minotari_console_wallet"]