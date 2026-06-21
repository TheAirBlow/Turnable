# Turnable Service on Linux &nbsp;·&nbsp; [🇷🇺 RU](LINUX_RU.md)
## Installation from releases
1. Download the latest Linux binary from [releases](https://github.com/TheAirBlow/Turnable/releases)
2. Make it executable: `chmod +x turnable`
3. Optionally move it to your PATH: `sudo mv turnable /usr/local/bin/`

## Building from source
If you prefer to compile it yourself:
```bash
go build -o turnable ./cmd
```

## Installation
It's recommended that you install Turnable in `/opt/turnable`:
```bash
mkdir -p /opt/turnable
sudo cp turnable /opt/turnable/
```

## Configuration
Create your service configuration file at `/opt/turnable/service.json`:
```json
{
  "unix_socket": "/run/turnable/turnable.sock",
  "listen_addr": "127.0.0.1:9000"
}
```

For authentication and encryption, see the [setup guide](SETUP.md).

## Running the Service
Quick run:
```bash
sudo /opt/turnable/turnable service server -c /opt/turnable/service.json
```

Available flags:
```
-c, --config string   service config JSON file path (default "service.json")
-p, --persist string  directory to persist instance configs for auto-restart
-V, --verbose         enable verbose debug logging
```

## Running as a Systemd Service
Create `/etc/systemd/system/turnable.service`:
```ini
[Unit]
Description=Turnable Service Mode
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=/opt/turnable
ExecStart=/opt/turnable/turnable service server -c /opt/turnable/service.json -p /var/lib/turnable/instances
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=turnable

[Install]
WantedBy=multi-user.target
```

Setup and start:
```bash
sudo chown -R nobody:nogroup /opt/turnable/
sudo systemctl daemon-reload
sudo systemctl enable --now turnable
```

Manage the service:
```bash
sudo systemctl status turnable
sudo systemctl stop turnable
sudo systemctl restart turnable
```

## Socket Permissions
If using a Unix socket, ensure proper permissions for CLI clients:
```bash
sudo chmod 660 /run/turnable/turnable.sock
```

For multiple users, consider creating a group:
```bash
sudo groupadd -r turnable-clients
sudo usermod -a -G turnable-clients $USER
sudo chgrp turnable-clients /run/turnable
sudo chmod 770 /run/turnable
sudo chmod 660 /run/turnable/turnable.sock
```

## Connecting with CLI client
Once the service is running, connect with:
```bash
./turnable service client --unix /run/turnable/turnable.sock
```

With authentication:
```bash
./turnable service client \
  --address 127.0.0.1:9000 \
  --pub-key client_pub_key_base64 \
  --priv-key client_priv_key_base64
```

## Firewall Configuration
If using TCP listener (`listen_addr`), open the port:
```bash
sudo ufw allow 9000/tcp
```

For Unix socket, only local processes with proper permissions can connect.

## Logging
View systemd service logs:
```bash
sudo journalctl -u turnable -f
```

View persistent instance logs from the CLI client:
```bash
./turnable service client --unix /run/turnable/turnable.sock
> logs
```

## Troubleshooting
- **Socket permission denied**: Check socket and user permissions with `ls -la /run/turnable/`
- **Port already in use**: Change `listen_addr` in `service.json` or stop the conflicting service
- **Service won't start**: Check logs with `sudo journalctl -u turnable -n 50`
- **Cannot reach service**: Verify `unix_socket` or `listen_addr` is set and running with `ps aux | grep turnable`
- **Instance won't start**: Check logs for the instance in the CLI client

## Next Steps
- [Service Setup Guide](SETUP.md)
- [Server Configuration Reference](../server/CONFIG.md)