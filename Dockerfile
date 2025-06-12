FROM ubuntu:24.04
COPY ./target/debug/minotari_console_wallet /usr/local/bin/minotari_console_wallet
COPY config.toml /usr/local/bin/wallet_data/config.toml

# Default command (can be overridden)
ENTRYPOINT ["/usr/local/bin/minotari_console_wallet"]