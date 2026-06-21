# Turnable Server Configuration &nbsp;·&nbsp; [🇷🇺 RU](CONFIG_RU.md)
Server configuration uses a single JSON file that contains multiple servers and providers. Each server can use different platforms and providers.

## Basic Structure
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

## Server Configuration Fields
| Field         | Type   | Required | Description                                                     |
|---------------|--------|----------|-----------------------------------------------------------------|
| `type`        | string | Yes      | Connection type: `relay` (only type supported)                  |
| `platform_id` | string | Yes      | Platform ID (e.g., `vk.com`)                                    |
| `call_id`     | string | Yes      | Platform specific call or meeting ID                            |
| `pub_key`     | string | Yes      | Public key for encryption (base64, ML-KEM-768 format)           |
| `priv_key`    | string | Yes      | Private key matching the public key (base64, ML-KEM-768 format) |
| `proto`       | string | No       | Protocol (see [Protocols](../REFERENCE.md); defaults to `none`) |
| `listen_addr` | string | Yes      | Address to listen on (IP:port), usually `0.0.0.0:port`          |
| `public_ip`   | string | Yes      | Public IP or hostname clients connect to                        |
| `cloak`       | string | No       | Traffic obfuscation method (currently only `none`)              |
| `provider`    | string | Yes      | Provider ID to use for this server                              |

## Provider Types
### Raw Provider
Users and routes are embedded directly in the config file:
```json
{
  "providers": {
    "provider_main": {
      "type": "raw",
      "routes": [],
      "users": []
    }
  }
}
```

### JSON Provider
Users and routes are read from external files:
```json
{
  "providers": {
    "provider_file": {
      "type": "json",
      "path": "/path/to/provider.json"
    }
  }
}
```

The `provider.json` file has the same structure as the raw provider's routes and users.

## Routes
Each route describes a destination that clients can tunnel to:

| Field        | Type    | Required | Description                                                                           |
|--------------|---------|----------|---------------------------------------------------------------------------------------|
| `id`         | string  | Yes      | Unique route identifier                                                               |
| `address`    | string  | Yes      | Destination IP address                                                                |
| `port`       | integer | Yes      | Destination port (1-65535)                                                            |
| `socket`     | string  | Yes      | Socket type: `tcp` or `udp` (see [Socket Types](../REFERENCE.md))                     |
| `transport`  | string  | No       | Transport protocol (see [Transports](../REFERENCE.md); defaults to `none` if omitted) |
| `encryption` | string  | No       | Encryption mode (see [Encryption Modes](../REFERENCE.md); defaults to `handshake`)    |
| `name`       | string  | No       | Display name for this route                                                           |

> [!NOTE]
> TCP routes must use a transport protocol, preferably `kcp`, and UDP should use `none`.

## Users
Each user object defines access control and connection settings:

| Field            | Type    | Required | Description                                                                      |
|------------------|---------|----------|----------------------------------------------------------------------------------|
| `uuid`           | string  | Yes      | Unique user identifier (use [uuidgenerator.net](https://www.uuidgenerator.net/)) |
| `allowed_routes` | array   | Yes      | List of route IDs this user can access                                           |
| `type`           | string  | Yes      | Connection type: `relay` or `p2p`                                                |
| `peers`          | integer | Yes      | Number of peer connections per session (1 or more)                               |
| `forceturn`      | boolean | No       | Force TURN in P2P mode (optional)                                                |

> [!WARNING]
> User UUIDs are used for authentication. Treat them like passwords and never share them publicly.

For reference on protocols, transports, encryption modes, and socket types, see [REFERENCE.md](../REFERENCE.md).

## Generating Keys
To generate a new key pair for encryption:
```bash
./turnable config keygen
```