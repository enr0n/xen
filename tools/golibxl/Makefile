GOPATH ?= $(HOME)/go
PATH := $(GOPATH)/bin:$(PATH)

.PHONY: all
all: generate

.PHONY: generate
generate:
	c-for-go -ccincl libxl.yml

.PHONY: test
test:
	go test -v ./libxl -count=1

.PHONY: check
check: all test

.PHONY: clean
clean:
	rm -f libxl/cgo_helpers* const.go types.go doc.go libxl.go
