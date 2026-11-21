#!/usr/bin/env bash
ARCH=$(uname -m)

case "$ARCH" in
    aarch64) ARCH="arm64" ;;
    armv7l|armv8l) ARCH="arm" ;;
    x86_64)  ARCH="amd64" ;;
    i386|i686) ARCH="386" ;;
    *) echo "Unknown architecture: $ARCH"; exit 1 ;;
esac

echo "Downloading Turnable client for $ARCH..."
if curl --fail --output turnable -L "https://github.com/TheAirBlow/Turnable/releases/latest/download/turnable-android-$ARCH"; then
    chmod +x turnable
else
    echo "Failed to download client!"
    exit 1
fi

echo "Client successfully installed! Run ./turnable client --help to get started."
