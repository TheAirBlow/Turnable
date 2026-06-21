# VKontakte &nbsp;·&nbsp; [🇷🇺 RU](VK_RU.md)
The VKontakte platform module allows you to obtain authentication tokens through VK's video call system and make use of their TURN and SFU infrastructure. Follow this guide to set everything up securely without exposing your account to potential bans.

## Platform Specifications
| Feature                         | Value             | Notes                                                            |
|---------------------------------|-------------------|------------------------------------------------------------------|
| **Max TURN connections per IP** | 10                | Limits concurrent peer connections from same IP address          |
| **Relay bandwidth limit**       | 250 KB/s per peer | Outbound rate limit per peer connection in relay mode            |
| **P2P bandwidth limit**         | Unlimited         | No rate limiting in P2P mode                                     |
| **TURN security**               | Insecure          | Platform allows arbitrary connections to any IP via TURN         |
| **Auth security**               | Insecure          | Platform allows multiple anonymous identities from same IP       |
| **Per-IP rate limiting**        | Yes               | TURN server limits are enforced per IP address, not account      |
| **Shared TURN limits**          | No                | You can use 20 peers since VK provides 2 TURN servers by default |

## 1. Obtain a call ID
To minimize the chance of tracing the request back to your VK account, obtain a public call ID by [searching `"vk.com/call/join"` on Google](https://www.google.com/search?q=%22vk.com%2Fcall%2Fjoin%22):

![Example](https://files.catbox.moe/ic6sf9.png)

The call ID is the alphanumeric string that appears after `https://vk.com/call/join/` in the URL.

## 2. Deal with captcha
Turnable attempts to solve captchas automatically. However, if automatic solving doesn't work, you'll need to complete the captcha manually. Follow these steps:

### 2.1. Obtain the tokens
When automatic solving fails, you'll see a log message like this:
```
2026-04-22 16:09:19.748 [INFO] manual captcha solve required userscript=http://localhost:1984/manual_captcha.user.js guide=http://localhost:1984/ url=https://vk.com/call/join/... timeout=10m0s
```

#### Step 1: Install TamperMonkey
Install the [TamperMonkey extension](https://addons.mozilla.org/en-US/firefox/addon/tampermonkey/). Firefox is recommended because it supports browser extensions even on mobile platforms, including Android. Make sure to grant TamperMonkey permission to run in Incognito mode.

![Tampermonkey](https://files.catbox.moe/y5vlyg.png)

#### Step 2: Install the userscript
Copy the `userscript` URL from the log message and open it in your browser. You should see the installation dialog:

![Installation](https://files.catbox.moe/pq98f9.png)

Click the **Install** button to add the userscript to your browser.

### 2.2. Complete the captcha
Navigate to the `url` from the log message and complete the captcha manually. The userscript will:
- Automatically click the **Join** button for you
- Capture the necessary authentication tokens
- Redirect you away from VK once complete

Though, make sure that you do the following:
- **Use Incognito mode** if you're already logged into VK, which is forced to prevent potential bans.
- **Use Incognito mode on Android** if you have the VK app installed to prevent automatic app redirection.
- **Enable Desktop Mode** in your browser to not get redirected to the mobile version of the website.

## 3. PROFIT!
The authentication tokens have been captured and you're ready to use the VK platform with Turnable.
