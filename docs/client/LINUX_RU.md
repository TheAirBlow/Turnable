# Turnable клиент на Linux &nbsp;·&nbsp; [🇬🇧 EN](LINUX.md)
## Установка с релизов
1. Скачай последний бинарник для Linux со [страницы релизов](https://github.com/TheAirBlow/Turnable/releases)
2. Сделай его исполняемым: `chmod +x turnable`
3. Опционально перемести в PATH: `sudo mv turnable /usr/local/bin/`

> [!NOTE]
> Если хочешь использовать скрипт `quick-client.sh`, следуй инструкциям в [гайде по установке для Android](ANDROID.md).

## Сборка из исходников
Если предпочитаешь компилировать сам:
```bash
go build -o turnable ./cmd
```

## Запуск клиента
```bash
./turnable client -l 127.0.0.1:1080 <config-файл-или-url>
```

Добавь `turnable.exe` в белый список твоего VPN или proxy клиента, и настрой его на использование `127.0.0.1:1080`.

## Запуск в фоне
Чтобы запустить клиент в фоне, используй:
```bash
./turnable client -l 127.0.0.1:1080 <config-файл-или-url> &
```

Или используй terminal multiplexer вроде `tmux` или `screen`.

## Далее
- [Гайд установки клиента](SETUP_RU.md)
- [Справка по конфигурации клиента](CONFIG_RU.md)
