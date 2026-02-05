# MITRE ATT&CK Mitigations Lookup Tool

Утилита для поиска всех техник и под-техник MITRE ATT&CK, которые смягчаются заданной контрмерой (mitigation). Поддерживает несколько форматов вывода и полностью соответствует принципам Cloud Native.

## Возможности

- **Поиск по идентификатору контрмеры** (например, `M1037`) или по её названию
- **Автоматическое скачивание** актуальной STIX-базы ATT&CK Enterprise
- **Гибкое кэширование** с поддержкой Docker volumes, tmpfs и отключения кэша
- **Несколько форматов вывода**:
  - Таблица (по умолчанию)
  - JSON
  - CSV
  - nGQL-запросы для Nebula Graph
- **Cloud Native готовность** - 12-Factor App, stateless, Docker-ready
- **Безопасность** - непривилегированный пользователь, read-only режим

### Установка и сборка

```bash
# Локальная сборка
go build -o mitremit mitre-mitigates.go

# Docker сборка
make docker-build

# Сборка для всех платформ
make build-all
```

### Использование

```bash
# Базовый пример (таблица):
./mitremit -mitigation M1037

# JSON вывод:
./mitremit -mitigation M1037 -json > output.json

# Поиск по названию:
./mitremit -mitigation-name "Filter Network Traffic" -csv

# Генерация nGQL-запросов:
./mitremit -mitigation M1037 -ngql > nebula_inserts.ngql

# Отключение кэша (для CI/CD):
./mitremit -mitigation M1037 --no-cache
```

### Docker использование

```bash
# Сборка образа:
make docker-build

# Запуск с локальным кэшем:
make docker-run

# Запуск без кэша:
make docker-run-nocache

# Запуск с Docker volume:
make docker-run-volume

# Shell в контейнере для отладки:
make docker-test
```

### Пример вывода

```
MITIGATION       Filter Network Traffic (M1037)
----------------------------------------------------------------
TECHNIQUE ID     TECHNIQUE NAME
T1071            Application Layer Protocol
T1565            Data Manipulation
T1573            Encrypted Channel
```

```json
[
  {
    "external_id": "T1071",
    "name": "Application Layer Protocol"
  },
  {
    "external_id": "T1565",
    "name": "Data Manipulation"
  }
]
```

```csv
Mitigation ID,Mitigation Name,Technique ID,Technique Name
M1037,Filter Network Traffic,T1071,Application Layer Protocol
M1037,Filter Network Traffic,T1565,Data Manipulation
```

```sql
INSERT VERTEX mitigation(id, name) VALUES `M1037`:("M1037", "Filter Network Traffic");
INSERT VERTEX technique(id, name) VALUES `T1071`:("T1071", "Application Layer Protocol");
INSERT EDGE mitigates() VALUES `M1037` -> `T1071`;
```

## Безопасность

### Особенности безопасности:
- **Непривилегированный пользователь** - контейнер запускается от appuser (UID 1000)
- **Read-only режим** - поддерживает запуск с флагом --read-only
- **Атомарная запись** - временные файлы для избежания race conditions
- **Ограничение размера** - защита от переполнения памяти при скачивании
- **Stateless** - кэш не сохраняется в образе, только в volumes

### Рекомендации для production:
1. Используйте Docker volumes для сохранения кэша
2. Регулярно обновляйте образ (скачивается свежая версия MITRE данных)
3. Используйте `--no-cache` в CI/CD пайплайнах
4. Рассмотрите запуск в read-only режиме для production
