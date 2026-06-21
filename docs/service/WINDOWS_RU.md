# Turnable Service на Windows &nbsp;·&nbsp; [🇬🇧 EN](WINDOWS.md)
## Установка
1. Скачайте последний Windows бинарник с [releases](https://github.com/TheAirBlow/Turnable/releases)
2. Создайте папку для Turnable (например, `C:\Turnable`)
3. Распакуйте бинарник в эту папку
4. Откройте Command Prompt или PowerShell в этой папке

> [!NOTE]
> Turnable работает только на Windows 10 и выше.

## Конфигурация
Создайте файл конфигурации сервиса (`service.json`) в папке Turnable:
```json
{
  "listen_addr": "127.0.0.1:9000"
}
```

Unix сокеты не поддерживаются на Windows. Вы должны использовать `listen_addr` с TCP конечной точкой. Для аутентификации и шифрования смотрите [SERVICE.md](SETUP.md).

## Запуск сервиса
```cmd
turnable.exe service server -c service.json
```

Для указания пользовательских путей конфигурации и сохранения:
```cmd
turnable.exe service server -c C:\Turnable\service.json -p C:\Turnable\instances
```

Доступные флаги:
```
-c, --config string   путь к JSON файлу конфигурации (по умолчанию "service.json")
-p, --persist string  директория для сохранения конфигураций для автозагрузки
-V, --verbose         включить подробное логирование отладки
```

## Запуск как Windows сервис
Используя NSSM (Non-Sucking Service Manager):

### Шаг 1: Скачайте NSSM
Скачайте NSSM с [nssm.cc/download](https://nssm.cc/download) и распакуйте его.

### Шаг 2: Установите сервис
Откройте PowerShell **как администратор** и выполните:
```powershell
cd C:\path\to\nssm\win64
.\nssm.exe install Turnable "C:\Turnable\turnable.exe" `
  "service server -c C:\Turnable\service.json -p C:\Turnable\instances"
```

### Шаг 3: Сконфигурируйте сервис
```powershell
# Установить автоматический перезапуск при ошибке
.\nssm.exe set Turnable Start SERVICE_AUTO_START
.\nssm.exe set Turnable AppRestartDelay 5000

# Перенаправить логи в файл
.\nssm.exe set Turnable AppStdout C:\Turnable\logs\turnable.log
.\nssm.exe set Turnable AppStderr C:\Turnable\logs\turnable.log
mkdir C:\Turnable\logs -ErrorAction SilentlyContinue
```

### Шаг 4: Запустите сервис
```powershell
.\nssm.exe start Turnable
```

Управление сервисом:
```powershell
# Проверить статус
.\nssm.exe status Turnable

# Остановить
.\nssm.exe stop Turnable

# Перезагрузить
.\nssm.exe restart Turnable

# Удалить сервис
.\nssm.exe remove Turnable confirm
```

## Конфигурация брандмауэра
Разрешите Turnable через Windows Firewall:
1. Перейдите в Control Panel > Windows Defender Firewall > Advanced settings
2. Нажмите "Inbound Rules" > "New Rule"
3. Выберите "Port" и выберите TCP
4. Укажите ваш порт (например, 9000)
5. Разрешите соединение

Или через PowerShell (как администратор):
```powershell
New-NetFirewallRule -DisplayName "Turnable Service" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9000
```

## Подключение с CLI клиентом
В новом Command Prompt или окне PowerShell:
```cmd
turnable.exe service client --address 127.0.0.1:9000
```

С аутентификацией:
```cmd
turnable.exe service client --address 127.0.0.1:9000 `
  --pub-key client_pub_key_base64 `
  --priv-key client_priv_key_base64
```

## Просмотр логов
Если вы сконфигурировали NSSM для логирования в файл:
```powershell
Get-Content C:\Turnable\logs\turnable.log -Tail 50 -Wait
```

Или в PowerShell:
```powershell
Get-EventLog -LogName Application -Source Turnable -Newest 50
```

Просмотр постоянных логов инстансов из CLI клиента:
```bash
turnable.exe service client --unix /run/turnable/turnable.sock
> logs
```

## Решение проблем
- **Порт уже используется**: Измените `listen_addr` в `service.json` или найдите конфликтующий процесс с помощью `netstat -ano | findstr :9000`
- **Сервис не запускается**: Проверьте логи NSSM в сконфигурированной директории логов
- **Не удается подключиться**: Убедитесь, что сервис запущен с помощью `.\nssm.exe status Turnable` и брандмауэр открыт
- **Инстанс не запускается**: Проверьте логи инстанса в CLI клиенте

## Следующие шаги
- [Гайд настройки сервиса](SETUP_RU.md)
- [Справка по конфигурации сервера](../server/CONFIG_RU.md)