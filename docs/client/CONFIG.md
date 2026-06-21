# Turnable Client Configuration &nbsp;·&nbsp; [🇷🇺 RU](CONFIG_RU.md)
Turnable client configs come in two formats: JSON and URL. They contain the same information but suit different use cases.

## JSON Format
A typical relay mode config looks like this:

```json
{
  "type": "relay",
  "platform_id": "vk.com",
  "user_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "call_id": "123456789",
  "routes": [
    {
      "route_id": "https",
      "socket": "tcp",
      "transport": "kcp"
    }
  ],
  "gateway": "203.0.113.45:56000",
  "proto": "dtls",
  "encryption": "handshake",
  "peers": 5,
  "pub_key": "AAAA+Db4QW...",
  "cloak": "none"
}
```

## URL Format
The same config in URL format:
```
turnable://user-uuid:call-id@vk.com/route-id?type=relay&gateway=203.0.113.45:56000&proto=dtls&encryption=handshake&peers=5&pub_key=AAAA%2BDb4QW...&cloak=none
```

The schema is as follows:
- `user`: User UUID
- `pass`: Call ID
- `host`: Platform ID
- `path`: Route IDs (slash-separated, can be multiple routes)
- `query`: Additional parameters (type, gateway, proto, encryption, peers, pub_key, cloak)
- `fragment`: Display name (optional)

## Configuration Fields
### Common Fields
| Field         | Type   | Required | Description                                |
|---------------|--------|----------|--------------------------------------------|
| `type`        | string | Yes      | Connection type: `relay` or `direct`       |
| `platform_id` | string | Yes      | Platform ID to use (e.g., `vk.com`)        |
| `user_uuid`   | string | Yes      | Your unique user identifier                |
| `call_id`     | string | Yes      | Platform specific call or meeting ID       |
| `routes`      | array  | Yes      | List of available routes to tunnel through |
| `name`        | string | No       | Display name for this configuration        |

### Route Fields
| Field       | Type   | Description                                                                      |
|-------------|--------|----------------------------------------------------------------------------------|
| `route_id`  | string | Unique identifier for this route                                                 |
| `socket`    | string | Socket type: `tcp` or `udp` (see [Socket Types](../REFERENCE.md))                |
| `transport` | string | Transport protocol: `kcp`, `sctp`, or `none` (see [Transports](../REFERENCE.md)) |

### Relay Mode Fields
| Field        | Type    | Required | Description                                               |
|--------------|---------|----------|-----------------------------------------------------------|
| `gateway`    | string  | Yes      | Server gateway address (IP:port)                          |
| `proto`      | string  | Yes      | Protocol (see [Protocols](../REFERENCE.md))               |
| `encryption` | string  | Yes      | Encryption mode (see [Encryption Modes](../REFERENCE.md)) |
| `peers`      | integer | Yes      | Number of peer connections (minimum 1)                    |
| `pub_key`    | string  | Yes      | Server's public key (base64 encoded, ML-KEM-768 format)   |
| `cloak`      | string  | No       | Traffic obfuscation method (currently only `none`)        |

### Direct Mode Fields
| Field     | Type    | Required | Description                            |
|-----------|---------|----------|----------------------------------------|
| `gateway` | string  | Yes      | Destination server address (IP:port)   |
| `peers`   | integer | Yes      | Number of peer connections (minimum 1) |

## Configuration Generation
To generate a client config from the server side, run the following command:
```bash
./turnable config generate <server-id> <user-uuid> <route-id1> [route-id2 ...]
```

Available flags:
```
-c, --config string   server config JSON file path (default "config.json")
-j, --json            output config in json format
```

The generated config is everything you need to provide to your users.