# Turnable &nbsp;·&nbsp; [🇷🇺 RU](README_RU.md)
Turnable is a VPN core that tunnels TCP/UDP traffic through [TURN](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT) relay servers or via [SFU](https://bloggeek.me/webrtcglossary/sfu/) provided by platforms like VKontakte. Traffic mimics legitimate WebRTC media and is encrypted, multiplexed, and spread across multiple peer connections. The entire codebase is modular and can be freely extended to add new features or support more platforms.

---

## Features
1. Future-proof modular architecture
2. Full support for both TCP and UDP sockets
3. Tunneling through multiple peer connections to bypass ratelimits
4. Multiplexing to allow establishing multiple route connections
5. End-to-end encryption - forced for handshake, optional for data
6. Convenient user and route management with proper authentication
7. Overall more stable and less hacky implementation than others

---

## How it works
There are two methods of establishing a tunnel with a remote server that Turnable supports. Both of them allow to establish multiple TCP/UDP connections via multiplexing, with traffic being spread through multiple peer connections to bypass platform ratelimits.

### Relay - tunnel via TURN with an intermediate
The client allocates a relay address on the platform's TURN server, connects to the Turnable server, and from there it forwards traffic to the configured destination. Simple and stable, but is usually heavily throttled and can be detected.

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

### Direct Relay - direct tunnel via TURN
The client allocates a relay address on the platform's TURN server and connects to the destination server directly. Does not require a Turnable server. **⚠️ Not recommended and is dangerous to use.**

```mermaid
sequenceDiagram
    participant App as Source
    participant TC as Turnable Client
    participant TURN as TURN Server
    participant Dest as Destination

    TC->>TURN: Join call, allocate relay endpoint
    Note over TC,Dest: Dedicated tunnel established

    loop Traffic
        App->>TC: TCP/UDP data
        TC->>Dest: Forwarded data
        Dest-->>TC: TCP/UDP data
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

If you would like to compile it yourself, run this command on the target machine:
```bash
go build -o turnable ./cmd
```

Check out the [ci.yml](https://github.com/TheAirBlow/Turnable/blob/main/.github/workflows/ci.yml) workflow for cross-compilation.

---

## Setup
### Server
Turnable provides end-to-end encryption, user and route management for your convenience. You need a VPS with a public IP and an internet connection, on which you are able to open ports freely. Keep in mind that Turnable is just a tunnel - you still need to set up a VPN/Proxy server. It is recommended that you use [WireGuard](https://www.wireguard.com/quickstart/).

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
| `call_id`              | Platform specific call or meeting ID                        |
| `priv_key` / `pub_key` | Key pair for end-to-end encryption                          |
| `relay.enabled`        | Relay mode enabled flag                                     |
| `relay.proto`          | Transport protocol (`dtls` / `srtp`)                        |
| `relay.cloak`          | Traffic obfuscation method (`none` for now)                 |
| `relay.public_ip`      | Public IP address of this server                            |
| `relay.port`           | UDP port for the DTLS/SRTP listener                         |
| `p2p.enabled`          | P2P mode enabled flag **⚠️ WIP**                            |

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
                "username": "Maxim Smirnov  ",
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

| Field                              | Description                                         |
|------------------------------------|-----------------------------------------------------|
| `routes[].id`                      | Unique route identifier                             |
| `routes[].address`                 | Destination address to forward traffic to           |
| `routes[].port`                    | Destination port                                    |
| `routes[].socket`                  | Socket type (`tcp` / `udp`)                         |
| `routes[].transport`               | Transport layer - use `kcp` for TCP, `none` for UDP |
| `routes[].client_prefs.username`   | Username to use in the call                         |
| `routes[].client_prefs.type`       | Connection type (`relay` / `p2p`)                   |
| `routes[].client_prefs.encryption` | Encryption mode (`handshake` / `full`)              |
| `routes[].client_prefs.name`       | Human-readable display name for this route          |
| `routes[].client_prefs.peers`      | Number of peer connections to establish             |
| `users[].uuid`                     | Unique user identifier                              |
| `users[].allowed_routes`           | List of route IDs this user is permitted to access  |

> [!WARNING]
> Do not share the user UUID willy-nilly, as it is used for authentication!

#### 4. Start the server
```bash
./turnable server
```

```
Flags:
  -c, --config string   server config JSON file path (default "config.json")
  -s, --store string    server user/route store JSON file path (default "store.json")
  -V, --verbose         enable verbose debug logging
```

#### 5. Generate client config
```bash
./turnable config <route-id> <user-uuid>
# turnable://user:pass@vk.com/https?pub_key=...&type=relay&...
```

```
Flags:
  -c, --config string   server config JSON file path (default "config.json")
  -j, --json            output config in json format
  -s, --store string    server user/route store JSON file path (default "store.json")
```

Produced config URL or JSON is the only thing you need to provide to your users.

---

### Client
Setting up a Turnable client is almost effortless. On android, its recommended that you use [Termux](https://f-droid.org/en/packages/com.termux/). Keep in mind that Turnable is just a tunnel - you still need to set up a VPN/Proxy client. It is recommended that you use [WireGuard](https://www.wireguard.com/quickstart/).

#### 1. Obtain your config from the server admin
#### 2. Start the client
```bash
./turnable client -l 127.0.0.1:1080 [config-url]
```

```
Flags:
  -c, --config string    client config JSON file path (default "config.json")
  -l, --listen string    local TCP/UDP listen address (ip:port) (default "127.0.0.1:0")
  -i, --no-interactive   disable interactive mode
  -V, --verbose          enable verbose debug logging
```

You can either specify a path to the JSON file, or the configuration URL.

#### 3. Point your app at the local address
Configure your proxy/VPN client application to use `127.0.0.1:1080` (or whatever address you chose)

---

## Reference
### Platforms
| ID       | Description                                                                                                   |
|----------|---------------------------------------------------------------------------------------------------------------|
| `vk.com` | Authenticates anonymously through [VKontakte](https://vk.com) and joins a meeting. [Usage guide](docs/VK.md). |

### Connection types
| Type     | Description                                                                                                                                    |
|----------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `relay`  | Tunnels traffic through the platform's TURN server to the Turnable server gateway.                                                             |
| `direct` | Tunnels traffic through the platform's TURN server directly to the destination server gateway. **⚠️ Not recommended and is dangerous to use.** |
| `p2p`    | Hides traffic inside fake screencasts routed through the platform's SFU. Requires SRTP and enabled Cloak. **⚠️ WIP**                           |

### Protocols
| Protocol | Description                                                         |
|----------|---------------------------------------------------------------------|
| `none`   | No protocol at all. **⚠️ Not recommended and is dangerous to use.** |
| `dtls`   | Raw DTLS. Simple but detectable. Only supported in `relay` mode.    |
| `srtp`   | DTLS+SRTP. Mimics real media traffic. Forced in `p2p` mode.         |

### Transports
| Transport | Description                                                                                                                                      |
|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `kcp`     | [KCP](https://github.com/xtaci/kcp-go) - reliable and stable ordered stream over UDP. Recommended for TCP routes.                                |
| `sctp`    | [SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol) - good enough, but not really ideal for our usecase. Not recommended. |

### Encryption modes
| Mode        | Description                                                 |
|-------------|-------------------------------------------------------------|
| `handshake` | Encrypts only the initial handshake. Faster, less overhead. |
| `full`      | Encrypts all traffic end-to-end.                            |

---

## Missing features
- Built-in WireGuard / SOCKS5 server and client
- Traffic obfuscation (cloak) implementations
- Database user and route management
- P2P connection type (via SFU)
- Android app

---

## Credits
- [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) - original project, on which Turnable is partially based on.

---

## License
[GNU General Public License v2.0](https://github.com/TheAirBlow/Turnable/blob/main/LICENCE)
