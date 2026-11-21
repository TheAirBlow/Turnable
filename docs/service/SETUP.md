# Turnable Service Mode Setup &nbsp;·&nbsp; [🇷🇺 RU](SETUP_RU.md)
Service mode provides a management layer for running multiple Turnable server or client instances. It exposes a control protocol over Unix sockets or TCP, allowing you to create, start, stop, and manage instances dynamically without restarting.

## Platform specific guides
- [Windows Service Setup](WINDOWS.md)
- [Linux Service Setup](LINUX.md)

## Key Features
- Run multiple relay server or client instances from a single service
- Manage instances dynamically via a CLI client or programmatically
- Optional encryption and authentication using ML-KEM-768
- Automatic persistence and instance auto-restart
- Structured logging with real-time streaming
- Unix socket or TCP listeners

1. Generate encryption keys (optional)
For a secure setup with authentication, generate ML-KEM-768 keypairs:

```bash
./turnable config keygen
```

You'll get output like:
```
priv_key=whH/S/GPFJ37zGv8n...
pub_key=BWEx0ygunbFJFCrIN...
```

The service will use these for encryption. Generate separate keypairs for the server and for each client that needs access.

## 2. Create service configuration
Create a `service.json` file:

```json
{
  "unix_socket": "/tmp/turnable.sock",
  "listen_addr": "127.0.0.1:9000",
  "pub_key": "BWEx0ygunbFJFCrIN...",
  "priv_key": "whH/S/GPFJ37zGv8n...",
  "allowed_keys": [
    "client_pub_key_1_base64",
    "client_pub_key_2_base64"
  ],
  "readonly_keys": [
    "panel_pub_key_base64"
  ],
  "persist_dir": "/var/lib/turnable/instances"
}
```

### Configuration Fields
| Field          | Required | Description                                                        |
|----------------|----------|--------------------------------------------------------------------|
| `unix_socket`  | No       | Path to Unix socket for local clients (e.g., `/tmp/turnable.sock`) |
| `listen_addr`  | No       | TCP address and port (e.g., `127.0.0.1:9000` or `0.0.0.0:9000`)    |
| `pub_key`      | No       | Server's public ML-KEM-768 key for authentication (base64)         |
| `priv_key`     | No       | Server's private ML-KEM-768 key for decryption (base64)            |
| `allowed_keys` | No       | Client public keys with full control (base64)                      |
| `readonly_keys`| No       | Client public keys that may only read: list, get, stats, sessions  |
| `persist_dir`  | No       | Directory to auto-load and persist providers and instance configs  |

> [!NOTE]
> At least one of `unix_socket` or `listen_addr` must be set. If no keypair is provided, the service runs with no authentication and logs a warning, so anyone who can reach a listener has full control. With a keypair but no `allowed_keys`, any client holding a keypair can connect. Clients prove they own the private key of the public key they present, so a leaked public key alone is not enough.

## 3. Start the service
```bash
./turnable service server -c service.json -p /var/lib/turnable/instances
```

Available flags:
```
-c, --config string   service config JSON file path (default "service.json")
-p, --persist string  directory to persist instance configs for auto-restart
-V, --verbose         enable verbose debug logging
```

## 4. Connect with the CLI client
In another terminal, start the CLI client:

```bash
./turnable service client --unix /tmp/turnable.sock
```

Or connect via TCP with authentication:
```bash
./turnable service client \
  --address 127.0.0.1:9000 \
  --pub-key client_pub_key_base64 \
  --priv-key client_priv_key_base64
```

Available flags:
```
-u, --unix string        unix socket file path to connect to
-a, --address string     TCP address and port to connect to
-p, --pub-key string     client public ML-KEM-768 key for auth (base64)
-k, --priv-key string    client private ML-KEM-768 key for auth (base64)
-s, --server-key string  service public ML-KEM-768 key to pin (base64)
```

Pass the service's `pub_key` as `--server-key` so the client refuses to talk to anything else. Without it, the client trusts whichever key the service presents.

## 5. Manage instances in the CLI
Once connected to the service, you can use commands. Type `help` for a list of commands.

Providers are always persisted. Instances created with `autostart` set to `true` (the optional last argument of `start-server` and `start-client`) are started again on service start, and a failed start or an unexpected stop is retried with a growing delay of 2 to 60 seconds. Instances without `autostart` come back stopped.

| Command | What it does |
|---|---|
| `stop <id>` | Stops an instance and removes it with its persisted record |
| `stop <id> keep` | Stops an instance but keeps it listed and persisted, it stays stopped after a service restart |
| `restart <id>` | Rebuilds an instance from its stored config and starts it, also works for stopped and failed ones |
| `update-instance <id> [name=] [autostart=] [config=] [listen=]` | Changes an instance, a new `config` or `listen` restarts it |
| `update-provider <uuid> [name=] [config=]` | Renames a provider or reloads it with a new config of the same type |
| `add-route` / `update-route` | Adds or replaces a route: `<provider> <id> <address:port> [socket] [transport] [encryption] [name]` |
| `add-user` / `update-user` | Adds or replaces a user: `<provider> <uuid> [type] [peers] [allowed_routes] [forceturn]` |

`delete-instance <id>` does the same as `stop <id>`. A request that gets no answer within 30 seconds fails with a timeout and the connection stays usable, since responses carry the ID of their request. A host that fails the handshake 5 times within a minute is blocked for a minute.

## 6. Stats and control for panels
Server instances count traffic per user and keep track of live sessions, so a panel does not need to guess:

| Command (`pkg/service` client method) | What it does |
|---|---|
| `stats <id> [collect [ack]]` (`GetStats`, `CollectStats`) | Server totals and every user seen: traffic, live tunnels, connected IPs, last seen. With `collect` it also returns what each user moved since the previous collect and starts counting again, which is what a panel polls to add usage up. With an `ack` token (`CollectStats`), a batch is repeated until the panel sends back its `collect_token`, so a lost response loses nothing |
| `sessions <id>` (`ListSessions`) | Live sessions with their user, route, address and traffic |
| `kick-user <id> <user_uuid>` (`KickUser`) | Closes all tunnels of a user, they can reconnect unless removed from the provider |
| `kick-session <id> <session_id>` (`KickSession`) | Closes all tunnels of a session |

Tunnel open and close events are pushed to every connected client as `SessionEvent` (`EventSession` in the Go client). Deleting a user from a provider also closes their live tunnels. Traffic is counted from the server's point of view: up is what clients sent into the tunnel, down is what came back.

Usage not yet collected is saved to the persist directory every 30 seconds and when the service stops, so a restart keeps it. A hard crash can lose up to 30 seconds.

Embedding the server directly? `engine.TurnableServer` has the same data as methods: `Stats`, `Users`, `User`, `CollectUsage`, `Sessions`, `KickUser`, `KickSession` and `Subscribe`.

## 7. Custom service clients
For integration with your own tools, you can implement a custom client. See [service.proto](/pkg/service/proto/service.proto), [conn.go](/pkg/service/conn.go) for the handshake and [encryption.go](/pkg/service/encryption.go) for the protocol and encryption specification.

## Detailed Configuration
For detailed information about server and client configurations, see:
- [Server Configuration](../server/CONFIG.md)
- [Client Configuration](../client/CONFIG.md)