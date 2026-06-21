# Turnable Client Setup Guide &nbsp;·&nbsp; [🇷🇺 RU](SETUP_RU.md)
## Quick Start
Keep in mind that Turnable is just a tunnel, you still need a VPN or proxy client. We recommend [WireGuard](https://www.wireguard.com/quickstart/).

## Platform specific guides
- [Android Setup](ANDROID.md)
- [Windows Setup](WINDOWS.md)
- [Linux Setup](LINUX.md)

### 1. Get a client config
Ask the server operator for a config file or generate one yourself. You'll receive a JSON file or a turnable:// URL.

### 2. Run the client
```bash
./turnable client -l 127.0.0.1:1080 <config-file-or-url>
```

The client listens on the address you specified (default is `127.0.0.1:1080`).

### 3. Connect your app
Point your VPN or proxy client to the address where Turnable is listening. That's it!

## Command flags
```
-c, --config string    client config JSON file path (default "config.json")
-l, --listen string    local TCP/UDP listen address (ip:port) (default "127.0.0.1:0")
-i, --no-interactive   disable interactive mode
-V, --verbose          enable verbose debug logging
```

You can pass either a path to a JSON file or a configuration URL.

## Direct relay to a UDP server
If you want to connect directly to a server without a Turnable server intermediary, you can generate a direct config:

```bash
./turnable config direct <platform-id> <call-id> <username> <gateway-addr> -n [peers]
```

Flags:
```
-n, --peers int   how many peer connections to use (default 1)
-j, --json        output config in json format
```

> [!WARNING]
> This is insecure and not recommended. Use only if you know what you're doing.

## Detailed Configuration
For detailed information about client configuration options, see [CONFIG.md](CONFIG.md).


