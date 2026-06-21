# Turnable Server Setup Guide &nbsp;·&nbsp; [🇷🇺 RU](SETUP_RU.md)
## Quick Start
Keep in mind that Turnable is just a tunnel, you still need a VPN or proxy client. We recommend [WireGuard](https://www.wireguard.com/quickstart/).

## Platform specific guides
- [Windows Setup](WINDOWS.md)
- [Linux Setup](LINUX.md)

### 1. Generate encryption keys
```bash
./turnable config keygen
```

You'll get output like:
```
priv_key=whH/S/GPFJ37zGv8n...
pub_key=BWEx0ygunbFJFCrIN...
```

### 2. Create configuration
Create a `config.json` file with your servers and providers:
```json
{
  "servers": {
    "main": {
      "type": "relay",
      "platform_id": "vk.com",
      "call_id": "123456789",
      "pub_key": "BWEx0ygunbFJFCrIN...",
      "priv_key": "whH/S/GPFJ37zGv8n...",
      "proto": "dtls",
      "listen_addr": "0.0.0.0:56000",
      "public_ip": "203.0.113.45",
      "cloak": "none",
      "provider": "provider_main"
    }
  },
  "providers": {
    "provider_main": {
      "type": "raw",
      "routes": [
        {
          "id": "https",
          "address": "127.0.0.1",
          "port": 443,
          "socket": "tcp",
          "transport": "kcp",
          "encryption": "handshake",
          "name": "HTTPS Server"
        }
      ],
      "users": [
        {
          "uuid": "550e8400-e29b-41d4-a716-446655440000",
          "allowed_routes": ["https"],
          "type": "relay",
          "peers": 5
        }
      ]
    }
  }
}
```

Generate UUIDs at [uuidgenerator.net](https://www.uuidgenerator.net/).

### 3. Start the server
```bash
./turnable server
```

Available flags:
```
-c, --config string   server config JSON file path (default "config.json")
-V, --verbose         enable verbose debug logging
```

### 4. Generate client configs
Create a config for each user:
```bash
./turnable config generate <server-id> <user-uuid> <route-id1> [route-id2 ...]
```

Flags:
```
-c, --config string   server config JSON file path (default "config.json")
-j, --json            output config in json format
```

The generated URL or JSON is all you need to send to your users.

## Detailed Configuration
For detailed information about server configuration options, see [CONFIG.md](CONFIG.md).