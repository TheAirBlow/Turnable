# Android Setup &nbsp;·&nbsp; [🇷🇺 RU](ANDROID_RU.md)
This guide helps you set up the Turnable VPN client on Android using Termux and NekoBox. It assumes you have a Turnable server running with a configured WireGuard route, though it generally applies to any UDP based protocol. Users of TCP based protocols can just ignore MTU recommendations.

## 1. Install Termux
First of all, you need to install Termux, as there is no official Turnable app for Android yet. **Do not use Google Play Store version** as it is severely outdated. Instead, download it from their [GitHub Releases](https://github.com/termux/termux-app/releases/latest) page.

When downloading, select the correct architecture for your device:
- **arm64** - Most modern Android phones
- **armeabi-v7a** - Older Android devices
- **x86** - Some tablets and emulators

## 2. Set up the client
### 2.1. Quick setup
Run the quick setup script to download and configure the Turnable client:

```bash
curl -sSfL https://raw.githubusercontent.com/TheAirBlow/Turnable/refs/heads/main/scripts/quick-client.sh | bash
```

It's recommended to create a dedicated directory first:

```bash
mkdir Turnable
cd Turnable
# ... now run the curl command from above
```

### 2.2. After installation
The script creates the following files:

| File            | Purpose                                       |
|-----------------|-----------------------------------------------|
| `turnable`      | The main VPN client executable                |
| `run-client.sh` | Script to start the client with configuration |
| `update.sh`     | Script to update to the latest version        |

**Usage:**
```bash
# Start the client
./run-client.sh <listen_addr> <config_file> [additional_args...]

# Update to latest version
./update.sh
```

**Parameters:**
- `<listen_addr>` - Socket listening address, e.g., `127.0.0.1:PORT` for local-only, or `0.0.0.0:PORT` for network access.
- `<config_file>` - Path to your configuration, can be a JSON file or text file with a config URL.

### 2.3. Configure with a config URL
If you have a configuration URL, store it in a text file:

```bash
# ... echo it directly to the file
echo "your_config_url_here" > wireguard.txt
# ... or use a text editor
nano wireguard.txt
# ... past the config URL, then press Ctrl+S to save and Ctrl+X to exit
```

Then start the client:
```bash
./run-client.sh 127.0.0.1:5080 wireguard.txt
```

### 2.4. Configure with a JSON file
If you have a JSON configuration file, place it in the same directory and use it directly:

```bash
./run-client.sh 127.0.0.1:5080 config.json
```

## 3. Set up NekoBox
NekoBox is a proxy client for Android that will route your traffic through the Turnable client. Install it from the [official repository](https://github.com/MatsuriDayo/NekoBoxForAndroid) or your device's app store.

### 3.1. Configure routing rules
Delete all pre-existing routing rules and add the following to block ads, protect against spyware, and optimize routing:

| # | Name                   | Domain/IP                  | Outbound | Purpose                           |
|---|------------------------|----------------------------|----------|-----------------------------------|
| 1 | Block all ads          | `geosite:category-ads-all` | Bypass   | Prevents ad tracking              |
| 2 | Bypass Russian domains | `geosite:category-ru`      | Bypass   | Bypass local VPN restrictions     |
| 3 | Bypass Russian IPs     | `geoip:ru`                 | Bypass   | Bypass local VPN restrictions     |
| 4 | Block local socks5     | See below                  | Block    | Prevents outbound IP exposure     |
| 5 | App whitelist          | Configure per your needs   | Proxy    | Routes selected apps through VPN  |
| 6 | Bypass by default      | `0.0.0.0/0, ::/0`          | Bypass   | Bypass everything else by default |

**Custom JSON for rule #4:**
```json
{
  "inbound": ["mixed-in", "socks-in"],
  "outbound": "block"
}
```

### 3.2. Configure WireGuard
If you're creating a WireGuard configuration manually, ensure these fields are set correctly:

| Field             | Value              | Notes                                     |
|-------------------|--------------------|-------------------------------------------|
| Server            | `127.0.0.1:PORT`   | Use PORT from `run-client.sh`             |
| MTU               | `1280`             | Recommended for tunneling though Turnable |
| Private Key       | [Your private key] | From your client config                   |
| Server Public Key | [Server pub key]   | From your server config                   |
| Network Address   | [Your network]     | From your server config                   |

If you already have a NekoBox compatible WireGuard config, you can import it as-is, but you **must update** the Server and MTU fields as shown above, as otherwise it will either bypass Turnable entirely or performance would be severely hindered.

## 5. PROFIT!
Your Android device is now configured to route traffic through the Turnable VPN client. NekoBox will manage your VPN connection making use of the configured secure routing rules.