# Turnable Server on Windows &nbsp;·&nbsp; [🇷🇺 RU](WINDOWS_RU.md)

## Installation
1. Download the latest Windows binary from [releases](https://github.com/TheAirBlow/Turnable/releases)
2. Create a folder for Turnable (e.g., `C:\Turnable`)
3. Extract the binary into that folder
4. Open Command Prompt or PowerShell in that folder

> [!NOTE]
> Turnable only works on Windows 10 and above.

## Configuration
Create your configuration file (`config.json`) in the Turnable folder. See [Configuration Reference](CONFIG.md) for details.

## Running the Server
```cmd
turnable.exe server
```

To specify custom config and store file paths:
```cmd
turnable.exe server -c C:\path\to\config.json -s C:\path\to\store.json
```

Available flags:
```
-c, --config string   server config JSON file path (default "config.json")
-s, --store string    server user/route store JSON file path (default "store.json")
-V, --verbose         enable verbose debug logging
```

## Firewall Configuration
Allow the Turnable server port through Windows Firewall:
1. Go to Control Panel > Windows Defender Firewall > Advanced settings
2. Click "Inbound Rules" > "New Rule"
3. Select "Port" and choose UDP
4. Specify your port (e.g., 56000)
5. Allow the connection

## Next Steps
- [Server Setup Guide](SETUP.md)
- [Server Configuration Reference](CONFIG.md)

