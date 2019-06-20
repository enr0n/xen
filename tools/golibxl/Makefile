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
