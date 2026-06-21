# Turnable Reference &nbsp;·&nbsp; [🇷🇺 RU](REFERENCE_RU.md)
## Connection Types
| Type     | Description                                                                                                    |
|----------|----------------------------------------------------------------------------------------------------------------|
| `relay`  | Tunnels traffic through the platform's TURN server to the Turnable server gateway.                             |
| `direct` | Tunnels traffic through the platform's TURN server directly to the destination server. **⚠️ Not recommended.** |
| `p2p`    | Hides traffic inside fake screencasts routed through the platform's SFU. **⚠️ WIP**                            |

## Protocols
| Protocol | Description                                                           |
|----------|-----------------------------------------------------------------------|
| `none`   | No protocol at all. **⚠️ Not recommended and is dangerous to use.**   |
| `dtls`   | Raw DTLS. Simple but detectable. Only supported in `relay` mode.      |
| `srtp`   | DTLS+SRTP. Mimics real media traffic. Forced in `p2p` mode.           |

## Transports
| Transport | Description                                                                                                            |
|-----------|------------------------------------------------------------------------------------------------------------------------|
| `none`    | No transport protocol at all. Only use for UDP routes.                                                                 |
| `kcp`     | [KCP](https://github.com/xtaci/kcp-go) - reliable and stable ordered stream over UDP. Recommended for TCP routes.      |
| `sctp`    | [SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol) - supported but not ideal. Not recommended. |

## Socket Types
| Сокет | Описание                                                                                                |
|-------|---------------------------------------------------------------------------------------------------------|
| `tcp` | [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) connection (for VLESS, Trojan, etc.) |
| `udp` | [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) connection (for WireGuard, Hysteria, etc.)  |

## Encryption Modes
| Mode        | Description                                                 |
|-------------|-------------------------------------------------------------|
| `handshake` | Encrypts only the initial handshake. Faster, less overhead. |
| `full`      | Encrypts all traffic end-to-end.                            |
