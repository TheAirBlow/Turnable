# Turnable сервер на Windows &nbsp;·&nbsp; [🇬🇧 EN](WINDOWS.md)
## Установка
1. Скачай последний бинарник для Windows со [страницы релизов](https://github.com/TheAirBlow/Turnable/releases)
2. Создай папку для Turnable (например, `C:\Turnable`)
3. Извлеки бинарник в эту папку
4. Открой Command Prompt или PowerShell в этой папке

> [!NOTE]
> Turnable работает только на Windows 10 и выше.

## Конфигурация
Создай файл конфигурации (`config.json`) в папке Turnable. Смотри [Справку по конфигурации](CONFIG_RU.md) для деталей.

## Запуск сервера
```cmd
turnable.exe server
```

Чтобы указать пользовательские пути к конфиг и store файлам:
```cmd
turnable.exe server -c C:\path\to\config.json -s C:\path\to\store.json
```

Доступные флаги:
```
-c, --config string   путь к JSON конфигу сервера (по умолчанию "config.json")
-s, --store string    путь к JSON хранилищу пользователей/маршрутов (по умолчанию "store.json")
-V, --verbose         включить подробное debug логирование
```

## Конфигурация Firewall
Разреши порт Turnable сервера через Windows Firewall:
1. Перейди в Control Panel > Windows Defender Firewall > Advanced settings
2. Нажми "Inbound Rules" > "New Rule"
3. Выбери "Port" и выбери UDP
4. Укажи твой порт (например, 56000)
5. Разреши соединение

## Далее
- [Гайд установки сервера](SETUP_RU.md)
- [Справка по конфигурации сервера](CONFIG_RU.md)