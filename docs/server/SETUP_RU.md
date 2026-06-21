# Гайд по настройке сервера Turnable &nbsp;·&nbsp; [🇬🇧 EN](SETUP.md)
## Быстрый старт
Напоминаем, что Turnable - это утилита для туннелирования, вам всё равно нужен VPN или proxy клиент. Мы рекомендуем [WireGuard](https://www.wireguard.com/quickstart/).

## Гайды для конкретной платформы
- [Настройка на Windows](WINDOWS_RU.md)
- [Настройка на Linux](LINUX_RU.md)

### 1. Сгенерируй пару ключей
```bash
./turnable config keygen
```

Ты получишь вывод вроде:
```
priv_key=whH/S/GPFJ37zGv8n...
pub_key=BWEx0ygunbFJFCrIN...
```

### 2. Создай конфиг сервера
Создай файл `config.json`:
```json
{
  "servers": {
    "main": {
      "type": "relay",
      "platform_id": "vk.com",
      "call_id": "123456789",
      "pub_key": "BWEx0ygunbFJFCrIN...",
      "priv_key": "whH/S/GPFJ37zGv8n...",
      "proto": "dtls",
      "listen_addr": "0.0.0.0:56000",
      "public_ip": "203.0.113.45",
      "cloak": "none",
      "provider": "provider_main"
    }
  },
  "providers": {
    "provider_main": {
      "type": "raw",
      "routes": [
        {
          "id": "https",
          "address": "127.0.0.1",
          "port": 443,
          "socket": "tcp",
          "transport": "kcp",
          "encryption": "handshake",
          "name": "HTTPS сервер"
        }
      ],
      "users": [
        {
          "uuid": "550e8400-e29b-41d4-a716-446655440000",
          "allowed_routes": ["https"],
          "type": "relay",
          "peers": 5
        }
      ]
    }
  }
}
```

Сгенерируй UUID на [uuidgenerator.net](https://www.uuidgenerator.net/).

### 3. Запусти сервер
```bash
./turnable server
```

Доступные флаги:
```
-c, --config string   путь к JSON конфигу сервера (по умолчанию "config.json")
-V, --verbose         включить подробное debug логирование
```

### 4. Сгенерируй конфигурации для клиентов
Создай конфиг для каждого пользователя:
```bash
./turnable config generate <server-id> <user-uuid> <route-id1> [route-id2 ...]
```

Флаги:
```
-c, --config string   путь к JSON конфигу сервера (по умолчанию "config.json")
-j, --json            вывести конфиг в формате JSON
```

Сгенерированный URL или JSON - это всё, что нужно отправить пользователю.

## Подробная конфигурация
Для подробной информации о параметрах конфигурации сервера смотри [CONFIG.md](CONFIG.md).