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

The client listens on the address you specified. Without `-l` it listens on `127.0.0.1` and uses the ports suggested by the config.

### 3. Connect your app
Point your VPN or proxy client to the address where Turnable is listening. That's it!

## Command flags
```
-l, --listen string    local TCP/UDP listen address (ip:port) (default "127.0.0.1:0")
-i, --no-interactive   disable interactive mode (does not open the browser for captchas)
-V, --verbose          enable verbose debug logging
```

The `[config]` argument is a configuration URL, a path to a JSON file, or a path to a text file holding a single-line URL. It defaults to `config.json`.

## Updating
```bash
./turnable update
```

It replaces the executable with the latest release. It refuses to run on dev builds or when already up to date unless you pass `-f`.

```
-f, --force   update even on dev builds or when already up to date
-c, --clean   remove leftover update files and exit
```

Each route listens on the port you pass with `-l`. When you pass none for a route, or port `0`, it uses the port the config suggests in `ports`, then the first address's port plus the route's index, then `10800` plus the route's index. Every route reuses the first address's host, so `-l 0.0.0.0:0` exposes all routes on the network with the suggested ports.

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


