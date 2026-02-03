.PHONY: build test lint fmt clean

BINARY_NAME=mitre-sync

build:
	go build -o ${BINARY_NAME} -v ./...

test:
	go test -v -race ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

clean:
	rm -f ${BINARY_NAME}
	rm -f coverage.out

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

docker-build:
	docker build -t ${BINARY_NAME}:latest .

docker-run:
	docker run --rm ${BINARY_NAME}:latest

all: fmt lint test build
