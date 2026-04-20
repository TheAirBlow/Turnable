# Turnable &nbsp;·&nbsp; [🇷🇺 RU](README_RU.md)
Turnable is a VPN core that tunnels TCP/UDP traffic through [TURN](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT) relay servers or via [SFU](https://bloggeek.me/webrtcglossary/sfu/) provided by platforms like VKontakte. From the platform's perspective, your client and server are just normal call participants. Traffic mimics legitimate WebRTC media and is encrypted, multiplexed, and spread across multiple peer connections.

---

## How it works
There are two methods of establishing a tunnel with a remote server. Both of them allow to establish multiple TCP/UDP connections via multiplexing, with traffic being spread through multiple peer connections to bypass platform ratelimits.

### Relay - direct tunnel via TURN
The server allocates a relay address on the platform's TURN server. The client connects to it, and from there the server forwards traffic to the configured destination. Simple and stable, but is usually heavily throttled and can be detected.

```mermaid
sequenceDiagram
    participant App as Source
    participant TC as Turnable Client
    participant TURN as TURN Server
    participant TS as Turnable Server
    participant Dest as Destination

    TC->>TURN: Join call, allocate relay endpoint
    Note over TC,TS: Dedicated tunnel established

    loop Traffic
        App->>TC: TCP/UDP data
        TC->>TS: Relay
        TS->>Dest: Forwarded data
        Dest-->>TS: TCP/UDP data
        TS->>TC: Relay
        TC-->>App: Forwarded data
    end
```

### P2P - fake screencast via SFU ⚠️ WIP
The client and server communicate through the platform's SFU, disguising all traffic as a screencast stream.

```mermaid
sequenceDiagram
    participant App as Source
    participant TC as Turnable Client
    participant SFU as SFU (VK)
    participant TSM as Server - Main Peer
    participant TSD as Server - Dedicated Peer
    participant Dest as Destination

    TC->>SFU: Join call, locate server main peer SSRC by username
    TC->>SFU: SDP response with main peer SSRC + start fake screencast
    TSM-->>TC: ready ack

    TC->>TSM: auth
    TSM-->>TC: auth ack + dedicated peer SSRC

    TC->>SFU: SDP response with dedicated peer SSRC
    TSD->>SFU: SDP response with client peer SSRC
    Note over TC,TSD: Dedicated tunnel established

    loop Traffic
        App->>TC: TCP/UDP data
        TC->>TSD: Relay
        TSD->>Dest: Forwarded data
        Dest-->>TSD: TCP/UDP data
        TSD->>TC: Relay
        TC-->>App: Forwarded data
    end
```

---

## Building
Pre-built binaries are available on the [releases page](https://github.com/TheAirBlow/Turnable/releases). Pick the correct file for your OS and architecture.

To build from source (run this on the target machine):
```bash
go build -o turnable ./cmd
```

Cross-compilation is handled by the CI pipeline - see `.github/workflows/` for reference.

---

## Setup
### Server
#### 1. Generate a key pair
```bash
./turnable keygen
# priv_key=whH/S/GPFJ37zGv8n...
# pub_key=BWEx0ygunbFJFCrIN...
```

#### 2. Write `config.json`
```json
{
    "platform_id": "vk.com",
    "call_id": "...",
    "priv_key": "...",
    "pub_key": "...",
    "relay": {
        "enabled": true,
        "proto": "dtls",
        "cloak": "none",
        "public_ip": "...",
        "port": 56000
    },
    "p2p": {
        "enabled": false
    }
}
```

| Field                  | Description                                                 |
|------------------------|-------------------------------------------------------------|
| `platform_id`          | Platform to use for signaling (see [Platforms](#platforms)) |
| `call_id`              | Platform-specific call/meeting ID                           |
| `priv_key` / `pub_key` | Key pair for end-to-end encryption                          |
| `relay.proto`          | Transport protocol (`dtls` / `srtp`)                        |
| `relay.cloak`          | Traffic obfuscation method (`none` for now)                 |
| `relay.public_ip`      | Public IP address of this server                            |
| `relay.port`           | UDP port for the DTLS/SRTP listener                         |
| `p2p.enabled`          | P2P mode - **not yet implemented**, keep `false`            |

#### 3. Write `store.json`
```json
{
    "routes": [
        {
            "id": "https",
            "address": "127.0.0.1",
            "port": 443,
            "socket": "tcp",
            "transport": "kcp",
            "client_prefs": {
                "username": "myuser",
                "type": "relay",
                "encryption": "handshake",
                "name": "My Server",
                "peers": 10
            }
        }
    ],
    "users": [
        {
            "uuid": "...",
            "allowed_routes": ["https"]
        }
    ]
}
```

| Field                              | Description                                                       |
|------------------------------------|-------------------------------------------------------------------|
| `routes[].id`                      | Unique route identifier                                           |
| `routes[].address`                 | Destination address to forward traffic to                         |
| `routes[].port`                    | Destination port                                                  |
| `routes[].socket`                  | Socket type (`tcp` / `udp`)                                       |
| `routes[].transport`               | Transport layer - use `kcp` for TCP routes, `none` for UDP routes |
| `routes[].client_prefs.username`   | Username embedded in the generated config URL                     |
| `routes[].client_prefs.type`       | Connection type (`relay` / `p2p`)                                 |
| `routes[].client_prefs.encryption` | Encryption mode (`handshake` / `full`)                            |
| `routes[].client_prefs.name`       | Human-readable display name for this route                        |
| `routes[].client_prefs.peers`      | Number of peer connections used for multiplexing                  |
| `users[].uuid`                     | Unique user identifier                                            |
| `users[].allowed_routes`           | List of route IDs this user is permitted to access                |

#### 4. Start the server
```bash
./turnable server
```

```
Flags:
  -c, --config string   server config JSON file path (default "config.json")
  -s, --store string    server user/route store JSON file path (default "store.json")
  -v, --verbose         enable verbose debug logging
```

#### 5. Generate client config URLs
```bash
./turnable config <route-id> <user-uuid>
# turnable://user:pass@vk.com/https?pub_key=...&type=relay&...
```

This URL is the only thing your users need.

```
Flags:
  -c, --config string   server config JSON file path (default "config.json")
  -s, --store string    server user/route store JSON file path (default "store.json")
```

---

### Client
#### 1. Obtain your config URL from the server admin.
#### 2. Start the client
```bash
./turnable client -l 127.0.0.1:1080 <config-url>
```

```
Flags:
  -l, --listen string   local TCP/UDP listen address (default "127.0.0.1:0")
  -v, --verbose         enable verbose debug logging
```

#### 3. Point your app at the local address
Configure your proxy/VPN client application to use `127.0.0.1:1080` (or whatever address you chose).

---

## Reference
### Platforms
| ID       | Description                                                                                                                                                                                                                              |
|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `vk.com` | Authenticates anonymously through [VKontakte](https://vk.com) and joins a meeting. Find open call IDs by searching [`"vk.com/call/join"` on Google](https://www.google.com/search?q=%22https%253A%252F%252Fvk.com%252Fcall%252Fjoin%22). |

### Connection types
| Type    | Description                                                                                                          |
|---------|----------------------------------------------------------------------------------------------------------------------|
| `relay` | Tunnels traffic through the platform's TURN servers directly to the server gateway.                                  |
| `p2p`   | Hides traffic inside fake screencasts routed through the platform's SFU. Requires SRTP and enabled Cloak. **⚠️ WIP** |

### Protocols
| Protocol | Description                                                    |
|----------|----------------------------------------------------------------|
| `dtls`   | Raw DTLS. Simple, detectable. Only supported in `relay` mode.  |
| `srtp`   | DTLS+SRTP. Mimics real media traffic. Required for `p2p` mode. |

### Transports
| Transport | Description                                                                                             |
|-----------|---------------------------------------------------------------------------------------------------------|
| `kcp`     | [KCP](https://github.com/xtaci/kcp-go) - reliable ordered stream over UDP. Recommended for TCP routes.  |
| `sctp`    | [SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol) - unstable, not recommended. |

### Encryption modes
| Mode        | Description                                                 |
|-------------|-------------------------------------------------------------|
| `handshake` | Encrypts only the initial handshake. Faster, less overhead. |
| `full`      | Encrypts all traffic end-to-end.                            |

---

## Missing features
- SRTP protocol to better mimic real media traffic
- Built-in WireGuard / SOCKS5 server and client
- Traffic obfuscation (cloak) implementations
- Database user and route management
- P2P connection type (via SFU)
- Android app

---

## License
[GNU General Public License v2.0](https://github.com/TheAirBlow/Turnable/blob/main/LICENCE)
