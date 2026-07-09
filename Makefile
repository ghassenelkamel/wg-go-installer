.PHONY: fmt test build docker-build docker-build-client server-menu server-up regenerate-configs generate-profiles client-menu

fmt:
	gofmt -w main.go cmd/wg-client/main.go main_test.go

test:
	go test ./...

build:
	go build -o wg-go-installer ./
	go build -o wg-client ./cmd/wg-client

docker-build:
	docker compose build wg

docker-build-client:
	docker compose --profile client build wg-client

server-menu:
	docker compose run --rm -it wg

server-up:
	docker compose run --rm wg up

regenerate-configs:
	docker compose run --rm wg regenerate-configs

generate-profiles:
	docker compose run --rm wg generate-profiles

client-menu:
	docker compose --profile client run --rm -it wg-client
