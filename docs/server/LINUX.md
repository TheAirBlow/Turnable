# Turnable Server on Linux &nbsp;·&nbsp; [🇷🇺 RU](LINUX_RU.md)
## Installation from releases
1. Download the latest Linux binary from [releases](https://github.com/TheAirBlow/Turnable/releases)
2. Make it executable: `chmod +x turnable`
3. Optionally move it to your PATH: `sudo mv turnable /usr/local/bin/`

## Building from source
If you prefer to compile it yourself:
```bash
go build -o turnable ./cmd
```

## Configuration
Create your configuration files. See [Configuration Reference](CONFIG.md) for details.

It's recommended that you install Turnable in `/opt/turnable`:
```bash
mkdir -p /opt/turnable
sudo cp turnable /opt/turnable/
```

## Running the Server
Quick run:
```bash
sudo /opt/turnable/turnable server -c /opt/turnable/config.json
```

Available flags:
```
-c, --config string   server config JSON file path (default "config.json")
-V, --verbose         enable verbose debug logging
```

## Running as a Systemd Service
Create `/etc/systemd/system/turnable.service`:
```ini
[Unit]
Description=Turnable VPN Tunnel Server
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=/opt/turnable
ExecStart=/opt/turnable/turnable server -c config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Setup and start:
```bash
sudo chown -R nobody:nogroup /opt/turnable
sudo systemctl daemon-reload
sudo systemctl enable --now turnable
```

Manage the service:
```bash
sudo systemctl status turnable
sudo systemctl stop turnable
sudo systemctl restart turnable
```

## Firewall Configuration
Allow the Turnable server port:
```bash
sudo ufw allow 56000/udp
```

If you configured a different port, replace `56000` with your chosen port number.

## Logging
To view systemd service logs:
```bash
sudo journalctl -u turnable -f
```

## Troubleshooting
- **Port already in use**: Change the port in `config.json`
- **Permission denied**: Run with `sudo` or use a port above 1024
- **Cannot reach server**: Check firewall rules with `sudo ufw status`
- **Service won't start**: Check logs with `sudo journalctl -u turnable -n 50`

## Next Steps
- [Server Setup Guide](SETUP.md)
- [Server Configuration Reference](CONFIG.md)



