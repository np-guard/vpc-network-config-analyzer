REPOSITORY := github.com/np-guard/vpc-network-config-analyzer
EXE:=vpcanalyzer

mod: go.mod
	@echo -- $@ --
	go mod tidy
	go mod download

fmt:
	@echo -- $@ --
	goimports -local $(REPOSITORY) -w .

lint:
	@echo -- $@ --
	CGO_ENABLED=0 go vet ./...
	golangci-lint run

precommit: mod fmt lint

build:
	@echo -- $@ --
	CGO_ENABLED=0 go build -o ./bin/$(EXE) ./cmd/analyzer

test:
	@echo -- $@ --
	go test ./... -v -cover -coverprofile analyzer.coverprofile
