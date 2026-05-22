.PHONY: test build vet fmt tidy ci

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

ci: vet test
