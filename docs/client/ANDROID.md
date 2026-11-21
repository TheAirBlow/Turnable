# Android Setup &nbsp;·&nbsp; [🇷🇺 RU](ANDROID_RU.md)
This guide helps you set up the Turnable VPN client on Android using Turnable App and Exclave. It assumes you have a Turnable server running with a configured WireGuard route, though it generally applies to any UDP based protocol. Users of TCP based protocols can just ignore MTU recommendations.

## 1. Install Turnable App
Turnable App is the official Turnable client for Android. It downloads and runs the Turnable core on first start, so you don't need to install Termux manually. Download the APK from the [releases page](https://github.com/TheAirBlow/TurnableApp/releases).

The first start needs internet access to download the core. If you prefer to run the core yourself, skip to [manual setup](#3-manual-setup).

## 2. Set up the client
### 2.1. Add a client
Open the **Clients** tab and add a subscription URL from your provider, or paste a `turnable://` link. The add menu has both.

### 2.2. Start the client
Start the clients you need. The app shows a listen address for each one, which your VPN or proxy client will connect to.

## 3. Manual setup
If you prefer to run the core yourself, you can use Termux instead. **Do not use Google Play Store version** as it is severely outdated. Instead, download it from their [GitHub Releases](https://github.com/termux/termux-app/releases/latest) page.

When downloading, select the correct architecture for your device:
- **arm64** - Most modern Android phones
- **armeabi-v7a** - Older Android devices
- **x86** - Some tablets and emulators

### 3.1. Quick setup
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

### 3.2. After installation
The script downloads the `turnable` executable into the current directory. Start the client with:

```bash
./turnable client -l <listen_addr> <config>
```

- `<listen_addr>` - Socket listening address, e.g., `127.0.0.1:PORT` for local-only, or `0.0.0.0:PORT` for network access.
- `<config>` - A config URL, a path to a JSON file, or a path to a text file with a config URL.

To update to the latest version:

```bash
./turnable update
```

### 3.3. Configure with a config URL
If you have a configuration URL, store it in a text file:

```bash
# ... echo it directly to the file
echo "your_config_url_here" > wireguard.url
# ... or use a text editor
nano wireguard.url
# ... past the config URL, then press Ctrl+S to save and Ctrl+X to exit
```

Then start the client:
```bash
./turnable client -l 127.0.0.1:5080 wireguard.url
```

### 3.4. Configure with a JSON file
If you have a JSON configuration file, place it in the same directory and use it directly:

```bash
./turnable client -l 127.0.0.1:5080 config.json
```

## 4. Set up Exclave
Exclave is a proxy client for Android that will route your traffic through the Turnable client. Install it from the [official repository](https://github.com/dyhkwong/Exclave) or your device's app store.

### 4.1. Configure routing rules
Delete all pre-existing routing rules and add the following to block ads, protect against spyware, and optimize routing:

| # | Name                   | Domain/IP                  | Outbound | Purpose                           |
|---|------------------------|----------------------------|----------|-----------------------------------|
| 1 | Block all ads          | `geosite:category-ads-all` | Bypass   | Prevents ad tracking              |
| 2 | Bypass Russian domains | `geosite:category-ru`      | Bypass   | Bypass local VPN restrictions     |
| 3 | Bypass Russian IPs     | `geoip:ru`                 | Bypass   | Bypass local VPN restrictions     |
| 4 | Block local socks5     | See below                  | Block    | Prevents outbound IP exposure     |
| 5 | Bypass by default      | `0.0.0.0/0, ::/0`          | Bypass   | Bypass everything else by default |

**Custom JSON for rule #4:**
```json
{
  "inbound": ["mixed-in", "socks-in"],
  "outbound": "block"
}
```

### 4.2. Configure the app whitelist
Open the **Settings** tab in Exclave, enable per-app proxy, and select only the apps that should go through Turnable. Do not set this up as a routing rule.

### 4.3. Configure WireGuard
If you're creating a WireGuard configuration manually, ensure these fields are set correctly:

| Field             | Value              | Notes                                     |
|-------------------|--------------------|-------------------------------------------|
| Server            | `127.0.0.1:PORT`   | Use the PORT shown in the app, or from `-l` in manual setup |
| MTU               | `1280`             | Recommended for tunneling though Turnable |
| Private Key       | [Your private key] | From your client config                   |
| Server Public Key | [Server pub key]   | From your server config                   |
| Network Address   | [Your network]     | From your server config                   |

If you already have an Exclave compatible WireGuard config, you can import it as-is, but you **must update** the Server and MTU fields as shown above, as otherwise it will either bypass Turnable entirely or performance would be severely hindered.

## 5. PROFIT!
Your Android device is now configured to route traffic through the Turnable VPN client. Exclave will manage your VPN connection making use of the configured secure routing rules.
