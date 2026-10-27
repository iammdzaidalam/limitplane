.PHONY: build test bench lint run docker compose-up compose-down prove

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/limitplane ./cmd/limitplane

test:
	go test -race ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt needed" && exit 1)

run:
	go run ./cmd/limitplane --config limitplane.example.json

docker:
	docker build -t limitplane:dev .

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down -v

prove:
	./scripts/prove-shared-limit.sh
