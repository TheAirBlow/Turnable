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

cat << 'EOF' > run-client.sh
#!/usr/bin/env bash
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <label> <file> [additional_args...]"
    echo "File can be either a path to a JSON configuration file, or to a text file which contains a config URL."
    echo "Set listen address to 127.0.0.1:PORT if you want to keep it local, or 0.0.0.0:PORT to make it accessible to others."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
BINARY="$SCRIPT_DIR/turnable"

if [[ ! -f "$BINARY" ]]; then
    echo "Error: 'turnable' binary not found in $SCRIPT_DIR"
    exit 1
fi

if [[ "$2" == *.json ]]; then
    "$BINARY" client -l "$1" -c "$2" "${@:3}"
else
    "$BINARY" client -l "$1" "$(cat "$2")" "${@:3}"
fi
EOF

chmod +x run-client.sh

cat << EOF > update.sh
#!/usr/bin/env bash
echo "Updating Turnable client for $ARCH..."
if curl --fail --output turnable -L "https://github.com/TheAirBlow/Turnable/releases/latest/download/turnable-android-$ARCH"; then
    chmod +x turnable
    echo "Client successfully updated!"
else
    echo "Failed to download client!"
    exit 1
fi
EOF

chmod +x update.sh

echo "Client successfully installed!"[]