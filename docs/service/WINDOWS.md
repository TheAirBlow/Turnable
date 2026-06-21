# Turnable Service on Windows &nbsp;·&nbsp; [🇷🇺 RU](WINDOWS_RU.md)
## Installation
1. Download the latest Windows binary from [releases](https://github.com/TheAirBlow/Turnable/releases)
2. Create a folder for Turnable (e.g., `C:\Turnable`)
3. Extract the binary into that folder
4. Open Command Prompt or PowerShell in that folder

> [!NOTE]
> Turnable only works on Windows 10 and above.

## Configuration
Create your service configuration file (`service.json`) in the Turnable folder:
```json
{
  "listen_addr": "127.0.0.1:9000"
}
```

Unix sockets are not supported on Windows. You must use `listen_addr` with a TCP endpoint. For authentication and encryption, see [SERVICE.md](SETUP.md).

## Running the Service
```cmd
turnable.exe service server -c service.json
```

To specify custom config and persistence directories:
```cmd
turnable.exe service server -c C:\Turnable\service.json -p C:\Turnable\instances
```

Available flags:
```
-c, --config string   service config JSON file path (default "service.json")
-p, --persist string  directory to persist instance configs for auto-restart
-V, --verbose         enable verbose debug logging
```

## Running as a Windows Service
Using NSSM (Non-Sucking Service Manager):

### Step 1: Download NSSM
Download NSSM from [nssm.cc/download](https://nssm.cc/download) and extract it.

### Step 2: Install the service
Open PowerShell **as Administrator** and run:
```powershell
cd C:\path\to\nssm\win64
.\nssm.exe install Turnable "C:\Turnable\turnable.exe" `
  "service server -c C:\Turnable\service.json -p C:\Turnable\instances"
```

### Step 3: Configure the service
```powershell
# Set to auto-restart on failure
.\nssm.exe set Turnable Start SERVICE_AUTO_START
.\nssm.exe set Turnable AppRestartDelay 5000

# Redirect logs to a file
.\nssm.exe set Turnable AppStdout C:\Turnable\logs\turnable.log
.\nssm.exe set Turnable AppStderr C:\Turnable\logs\turnable.log
mkdir C:\Turnable\logs -ErrorAction SilentlyContinue
```

### Step 4: Start the service
```powershell
.\nssm.exe start Turnable
```

Manage the service:
```powershell
# Check status
.\nssm.exe status Turnable

# Stop
.\nssm.exe stop Turnable

# Restart
.\nssm.exe restart Turnable

# Remove service
.\nssm.exe remove Turnable confirm
```

## Firewall Configuration
Allow Turnable through Windows Firewall:
1. Go to Control Panel > Windows Defender Firewall > Advanced settings
2. Click "Inbound Rules" > "New Rule"
3. Select "Port" and choose TCP
4. Specify your port (e.g., 9000)
5. Allow the connection

Or via PowerShell (as Administrator):
```powershell
New-NetFirewallRule -DisplayName "Turnable Service" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9000
```

## Connecting with CLI client
In a new Command Prompt or PowerShell window:
```cmd
turnable.exe service client --address 127.0.0.1:9000
```

With authentication:
```cmd
turnable.exe service client --address 127.0.0.1:9000 `
  --pub-key client_pub_key_base64 `
  --priv-key client_priv_key_base64
```

## Viewing Logs
If you configured NSSM to log to a file:
```powershell
Get-Content C:\Turnable\logs\turnable.log -Tail 50 -Wait
```

Or in PowerShell:
```powershell
Get-EventLog -LogName Application -Source Turnable -Newest 50
```

View persistent instance logs from the CLI client:
```bash
turnable.exe service client --unix /run/turnable/turnable.sock
> logs
```

## Troubleshooting
- **Port already in use**: Change `listen_addr` in `service.json` or find the conflicting process with `netstat -ano | findstr :9000`
- **Service won't start**: Check NSSM logs in the configured log directory
- **Cannot connect**: Verify the service is running with `.\nssm.exe status Turnable` and firewall is open
- **Instance won't start**: Check logs in the CLI client

## Next Steps
- [Service Setup Guide](SETUP.md)
- [Server Configuration Reference](../server/CONFIG.md)
