# Turnable Service на Linux &nbsp;·&nbsp; [🇬🇧 EN](LINUX.md)
## Установка из релизов
1. Скачайте последний Linux бинарник с [releases](https://github.com/TheAirBlow/Turnable/releases)
2. Сделайте его исполняемым: `chmod +x turnable`
3. Опционально переместите в PATH: `sudo mv turnable /usr/local/bin/`

## Компиляция из исходного кода
Если вы предпочитаете компилировать сами:
```bash
go build -o turnable ./cmd
```

## Установка
Рекомендуется установить Turnable в `/opt/turnable`:
```bash
mkdir -p /opt/turnable
sudo cp turnable /opt/turnable/
```

## Конфигурация
Создайте файл конфигурации сервиса в `/opt/turnable/service.json`:
```json
{
  "unix_socket": "/run/turnable/turnable.sock",
  "listen_addr": "127.0.0.1:9000"
}
```

Для аутентификации и шифрования смотрите [гайд по установке](SETUP_RU.md).

## Запуск сервиса
Быстрый запуск:
```bash
sudo /opt/turnable/turnable service server -c /opt/turnable/service.json
```

Доступные флаги:
```
-c, --config string   путь к JSON файлу конфигурации (по умолчанию "service.json")
-p, --persist string  директория для сохранения конфигураций для автозагрузки
-V, --verbose         включить подробное логирование отладки
```

## Запуск как Systemd сервис
Создайте `/etc/systemd/system/turnable.service`:
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

Настройка и запуск:
```bash
sudo chown -R nobody:nogroup /opt/turnable/
sudo systemctl daemon-reload
sudo systemctl enable --now turnable
```

Управление сервисом:
```bash
sudo systemctl status turnable
sudo systemctl stop turnable
sudo systemctl restart turnable
```

## Права доступа для сокета
Если используется Unix сокет, убедитесь в правильных правах доступа для CLI клиентов:
```bash
sudo chmod 660 /run/turnable/turnable.sock
```

Для нескольких пользователей рассмотрите создание группы:
```bash
sudo groupadd -r turnable-clients
sudo usermod -a -G turnable-clients $USER
sudo chgrp turnable-clients /run/turnable
sudo chmod 770 /run/turnable
sudo chmod 660 /run/turnable/turnable.sock
```

## Подключение с CLI клиентом
После запуска сервиса подключитесь с помощью:
```bash
./turnable service client --unix /run/turnable/turnable.sock
```

С аутентификацией:
```bash
./turnable service client \
  --address 127.0.0.1:9000 \
  --pub-key client_pub_key_base64 \
  --priv-key client_priv_key_base64
```

## Конфигурация брандмауэра
Если используется TCP сокет (`listen_addr`), откройте порт:
```bash
sudo ufw allow 9000/tcp
```

Для Unix сокета только локальные процессы с правильными правами могут подключиться.

## Логирование
Просмотр логов сервиса systemd:
```bash
sudo journalctl -u turnable -f
```

Просмотр постоянных логов инстансов из CLI клиента:
```bash
./turnable service client --unix /run/turnable/turnable.sock
> logs
```

## Решение проблем
- **Ошибка доступа к сокету**: Проверьте права доступа к сокету и пользователю с помощью `ls -la /run/turnable/`
- **Порт уже используется**: Измените `listen_addr` в `service.json` или остановите конфликтующий сервис
- **Сервис не запускается**: Проверьте логи с помощью `sudo journalctl -u turnable -n 50`
- **Не удается подключиться к сервису**: Убедитесь, что `unix_socket` или `listen_addr` установлены и сервис работает с помощью `ps aux | grep turnable`
- **Инстанс не запускается**: Проверьте логи инстанса в CLI клиенте

## Следующие шаги
- [Гайд настройки сервиса](SETUP_RU.md)
- [Справка по конфигурации сервера](../server/CONFIG_RU.md)