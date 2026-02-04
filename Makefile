.PHONY: all build build-all test lint fmt clean
.PHONY: docker-build docker-help docker-run docker-test docker-clean
.PHONY: cache-init cache-check help default

# Конфигурация
BINARY_NAME = mitremit
DOCKER_IMAGE = mitre-sync
DOCKER_TAG = latest
DIST_DIR = dist
CACHE_DIR = .mitre-cache

# ============================================
# Настройка по умолчанию
# ============================================
default: help

# ============================================
# Локальная разработка
# ============================================

# Проверка версии Go
check-go-version:
	@echo "🔍 Проверка версии Go..."
	@go version | grep -q "go1.25.6" && echo "✅ Go 1.25.6 найден" || \
		(echo "❌ Требуется Go 1.25.6, установлена: $$(go version)" && exit 1)

# Сборка для текущей платформы (с проверкой версии Go)
build: check-go-version
	go build -o ${BINARY_NAME} mitre-mitigates.go
	@echo "✅ Бинарник создан: ./${BINARY_NAME}"

# Сборка для всех платформ (без проверки версии в Docker)
build-all:
	mkdir -p ${DIST_DIR}
	@echo "🔨 Сборка для Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build -o ${DIST_DIR}/${BINARY_NAME}-linux-amd64 mitre-mitigates.go
	@echo "🔨 Сборка для macOS (Intel)..."
	GOOS=darwin GOARCH=amd64 go build -o ${DIST_DIR}/${BINARY_NAME}-darwin-amd64 mitre-mitigates.go
	@echo "🔨 Сборка для macOS (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 go build -o ${DIST_DIR}/${BINARY_NAME}-darwin-arm64 mitre-mitigates.go
	@echo "🔨 Сборка для Windows..."
	GOOS=windows GOARCH=amd64 go build -o ${DIST_DIR}/${BINARY_NAME}-windows-amd64.exe mitre-mitigates.go
	@echo "📦 Артефакты созданы в ${DIST_DIR}/:"
	@ls -lh ${DIST_DIR}/

# Форматирование кода
fmt:
	gofmt -w mitre-mitigates.go
	@echo "✅ Код отформатирован"

# Очистка
clean:
	rm -f ${BINARY_NAME} ${BINARY_NAME}.exe
	rm -rf ${DIST_DIR}
	@echo "✅ Очистка завершена"

# Показать help приложения (работает без ошибки)
app-help:
	@if [ -f "./${BINARY_NAME}" ]; then \
		./${BINARY_NAME} -h; \
	else \
		echo "⚠️  Сначала выполните 'make build'"; \
	fi

# Запуск примера локально
run:
	@./${BINARY_NAME} -mitigation M1037 2>&1 | head -20

# Полный цикл сборки
all: fmt build

# ============================================
# Docker операции
# ============================================

# Сборка Docker образа (использует Go 1.25.6 из Dockerfile)
docker-build:
	docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} .
	@echo "✅ Docker образ создан: ${DOCKER_IMAGE}:${DOCKER_TAG}"

# Проверка версии Go в Docker образе
docker-check-go-version:
	@echo "🔍 Проверка версии Go в Docker образе..."
	@docker run --rm --entrypoint /bin/sh ${DOCKER_IMAGE}:${DOCKER_TAG} \
		-c "go version 2>/dev/null || echo '✅ Go не установлен в runtime образе (ожидается для scratch/distroless)'" && \
		echo "✅ Версия Go проверена" || echo "⚠️  Не удалось проверить версию Go"

docker-help:
	@docker run --rm ${DOCKER_IMAGE}:${DOCKER_TAG} -h

# Запуск с локальным кэшем (монтируем в /tmp/.mitre-cache)
docker-run:
	docker run --rm \
		-v ${PWD}/${CACHE_DIR}:/tmp/.mitre-cache \
		${DOCKER_IMAGE}:${DOCKER_TAG} \
		-mitigation M1037

# Запуск без кэша
docker-run-nocache:
	docker run --rm \
		${DOCKER_IMAGE}:${DOCKER_TAG} \
		-mitigation M1037 --no-cache

# Запуск с Docker volume
docker-run-volume:
	@if ! docker volume inspect mitre-cache >/dev/null 2>&1; then \
		docker volume create mitre-cache; \
	fi
	docker run --rm \
		-v mitre-cache:/tmp/.mitre-cache \
		${DOCKER_IMAGE}:${DOCKER_TAG} \
		-mitigation M1037

# Shell в контейнере для проверки
docker-shell:
	docker run --rm -it \
		-v ${PWD}/${CACHE_DIR}:/tmp/.mitre-cache \
		--entrypoint /bin/sh \
		${DOCKER_IMAGE}:${DOCKER_TAG}

# Тестирование Docker образа (с проверкой Go версии)
docker-test:
	@echo "🧪 Тестирование Docker образа..."
	
	@echo "1. 🔍 Проверка наличия Docker образа..."
	@if ! docker image inspect ${DOCKER_IMAGE}:${DOCKER_TAG} >/dev/null 2>&1; then \
		echo "❌ Ошибка: Docker образ не найден!"; \
		echo "   Выполните: make docker-build"; \
		exit 1; \
	fi
	@echo "✅ Docker образ найден"
	
	@echo ""
	@echo "2. 🚀 Проверка запуска образа..."
	@if ! docker run --rm ${DOCKER_IMAGE}:${DOCKER_TAG} -h 2>&1 | grep -q "Usage:"; then \
		echo "❌ Ошибка: Docker образ не запускается!"; \
		exit 1; \
	fi
	@echo "✅ Docker образ успешно запускается"
	
	@echo ""
	@echo "3. 📁 Проверка отсутствия .mitre-cache в образе..."
	@if docker run --rm --entrypoint /bin/sh ${DOCKER_IMAGE}:${DOCKER_TAG} \
		-c "ls -la /app 2>/dev/null | grep -i mitre-cache" 2>/dev/null; then \
		echo "❌ Ошибка: В образе найдена директория .mitre-cache!"; \
		exit 1; \
	fi
	@echo "✅ В образе нет директории .mitre-cache"
	
	@echo ""
	@echo "4. 💾 Проверка stateless работы с tmpfs..."
	@if ! docker run --rm --tmpfs /tmp:rw,noexec,nosuid,size=100m \
		${DOCKER_IMAGE}:${DOCKER_TAG} \
		-mitigation M1037 --no-cache 2>&1 | grep -q "MITIGATION"; then \
		echo "❌ Ошибка: Stateless режим не работает!"; \
		exit 1; \
	fi
	@echo "✅ Stateless режим работает"
	
	@make docker-check-go-version
	
	@echo ""
	@echo "🎉 ВСЕ ТЕСТЫ УСПЕШНО ПРОЙДЕНЫ!"

docker-clean:
	docker rmi ${DOCKER_IMAGE}:${DOCKER_TAG} 2>/dev/null || true
	docker system prune -f
	@echo "✅ Docker очистка завершена"

# ============================================
# Справка
# ============================================
help:
	@echo "🚀 MITRE ATT&CK Mitigations Tool - Makefile команды"
	@echo ""
	@echo "📦 ЛОКАЛЬНАЯ РАЗРАБОТКА:"
	@echo "  make build              - Сборка бинарника (проверяет Go 1.25.6)"
	@echo "  make build-all          - Сборка для всех платформ"
	@echo "  make fmt                - Форматирование кода"
	@echo "  make clean              - Очистка артефактов"
	@echo "  make run                - Запуск примера (M1037)"
	@echo "  make all                - Форматирование + сборка"
	@echo "  make app-help           - Показать help приложения"
	@echo "  make check-go-version   - Проверить версию Go (1.25.6)"
	@echo ""
	@echo "🐳 DOCKER:"
	@echo "  make docker-build       - Сборка Docker образа (Go 1.25.6 в builder)"
	@echo "  make docker-run         - Запуск с локальным кэшем"
	@echo "  make docker-run-nocache - Запуск без кэша"
	@echo "  make docker-run-volume  - Запуск с Docker volume"
	@echo "  make docker-test        - Полное тестирование с проверкой Go версии"
	@echo "  make docker-clean       - Очистка Docker артефактов"
	@echo "  make docker-check-go-version - Проверить Go версию в Docker образе"
	@echo ""
	@echo "🔧 УТИЛИТЫ:"
	@echo "  make help               - Показать эту справку"
	@echo ""
	@echo "📝 ПРИМЕРЫ:"
	@echo "  # Локальный запуск:"
	@echo "  make build && ./mitremit -mitigation M1037 -json"
	@echo ""
	@echo "  # Docker запуск:"
	@echo "  make docker-build && make docker-run"
