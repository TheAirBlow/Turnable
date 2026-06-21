# Turnable сервер на Linux &nbsp;·&nbsp; [🇬🇧 EN](LINUX.md)
## Установка с релизов
1. Скачай последний бинарник для Linux со [страницы релизов](https://github.com/TheAirBlow/Turnable/releases)
2. Сделай его исполняемым: `chmod +x turnable`
3. Опционально перемести в PATH: `sudo mv turnable /usr/local/bin/`

## Сборка из исходников
Если предпочитаешь компилировать сам:
```bash
go build -o turnable ./cmd
```

## Конфигурация
Создай файлы конфигурации. Смотри [Справку по конфигурации](CONFIG_RU.md) для деталей.

Рекомендуется установить Turnable в `/opt/turnable`:
```bash
mkdir -p /opt/turnable
sudo cp turnable /opt/turnable/
```

## Запуск сервера
Быстрый запуск:
```bash
sudo /opt/turnable/turnable server -c /opt/turnable/config.json
```

Доступные флаги:
```
-c, --config string   путь к JSON конфигу сервера (по умолчанию "config.json")
-V, --verbose         включить подробное debug логирование
```

## Запуск как systemd сервис
Создай `/etc/systemd/system/turnable.service`:
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

Настройка и запуск:
```bash
sudo chown -R nobody:nogroup /opt/turnable
sudo systemctl daemon-reload
sudo systemctl enable --now turnable
```

Управление сервисом:
```bash
sudo systemctl status turnable
sudo systemctl stop turnable
sudo systemctl restart turnable
```

## Конфигурация Firewall
Разреши порт Turnable сервера:
```bash
sudo ufw allow 56000/udp
```

Если ты настроил другой порт, замени `56000` на номер твоего порта.

## Логирование
Для просмотра логов systemd сервиса:
```bash
sudo journalctl -u turnable -f
```

## Решение проблем
- **Порт уже занят**: Измени порт в `config.json`
- **Permission denied**: Запусти с `sudo` или используй порт выше 1024
- **Не можешь достучаться до сервера**: Проверь правила firewall с `sudo ufw status`
- **Сервис не запускается**: Проверь логи с `sudo journalctl -u turnable -n 50`

## Далее
- [Гайд установки сервера](SETUP_RU.md)
- [Справка по конфигурации сервера](CONFIG_RU.md)