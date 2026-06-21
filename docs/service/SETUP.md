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
| `allowed_keys` | No       | List of allowed client public keys that can connect (base64)       |
| `persist_dir`  | No       | Directory to auto-load and persist instance configurations         |

> [!NOTE]
> At least one of `unix_socket` or `listen_addr` must be set. If no keypair is provided, the service runs with no authentication. If authentication is enabled, `allowed_keys` is required.

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
-u, --unix string      unix socket file path to connect to
-a, --address string   TCP address and port to connect to
-p, --pub-key string   public ML-KEM-768 key for auth (base64)
-k, --priv-key string  private ML-KEM-768 key for auth (base64)
```

## 5. Manage instances in the CLI
Once connected to the service, you can use commands. Type `help` for a list of commands.

## 6. Custom service clients
For integration with your own tools, you can implement a custom client. See [service.proto](/pkg/service/proto/service.proto) and [encryption.go](/pkg/service/encryption.go) for the protocol and encryption specification.

## Detailed Configuration
For detailed information about server and client configurations, see:
- [Server Configuration](../server/CONFIG.md)
- [Client Configuration](../client/CONFIG.md)