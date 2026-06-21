# Turnable Client on Linux &nbsp;·&nbsp; [🇷🇺 RU](LINUX_RU.md)
## Installation from releases
1. Download the latest Linux binary from [releases](https://github.com/TheAirBlow/Turnable/releases)
2. Make it executable: `chmod +x turnable`
3. Optionally move it to your PATH: `sudo mv turnable /usr/local/bin/`

> [!NOTE]
> If you want to use the `quick-client.sh` script, follow the instructions in the [Android setup guide](ANDROID.md).

## Building from source
If you prefer to compile it yourself:
```bash
go build -o turnable ./cmd
```

## Running the client
```bash
./turnable client -l 127.0.0.1:1080 <config-file-or-url>
```

Add `turnable.exe` to the whitelist of your VPN or proxy client, and set it to use `127.0.0.1:1080`.

## Running in background
To run the client in the background, use:
```bash
./turnable client -l 127.0.0.1:1080 <config-file-or-url> &
```

Or use a terminal multiplexer like `tmux` or `screen`.

## Next Steps
- [Client Setup Guide](SETUP.md)
- [Client Configuration Reference](CONFIG.md)