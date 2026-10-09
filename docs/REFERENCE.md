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

## Session Transports
Relay mode only, chosen by the client's `mux` field. The server accepts both.

| Mux      | Description |
|----------|-------------|
| `mpath`  | Default. One multipath session over all peers: each peer is a path with its own sequence numbers, ACKs, RTT, loss detection and pacer (starts at ~180 KB/s, learns the real cap, backs off under policing). Packets go to the peer that delivers them first; reliable data is reassembled across peers, so reordering never causes retransmissions. Dead peers (no ACKs for 1.5 s) are dropped and redialed without disturbing streams. TCP routes are streams, UDP routes are datagrams. Always end-to-end encrypted (ML-KEM-768 + X25519, AES-256-GCM), with the server authenticated by `pub_key`. |
| `legacy` | Previous stack: per-route transport (KCP/SCTP) over tinymux, packets round-robined across peers. Kept for old servers. |

With `mpath`, `mask=on` (default) negotiates cheap masking in place of the outer DTLS/SRTP record encryption, since the payload is already encrypted: record shapes and sizes are unchanged, only the payload start is XOR-masked. Old servers ignore the offer and stay fully encrypted.

## Encryption Modes
| Mode        | Description                                                 |
|-------------|-------------------------------------------------------------|
| `handshake` | Encrypts only the initial handshake. Faster, less overhead. |
| `full`      | Encrypts all traffic end-to-end.                            |

Encryption modes apply to `mux=legacy` only; `mpath` always encrypts everything.
