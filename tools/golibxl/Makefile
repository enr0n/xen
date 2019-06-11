GOPATH ?= $(HOME)/go
PATH := $(GOPATH)/bin:$(PATH)

.PHONY: all
all: generate

.PHONY: generate
generate:
	c-for-go libxl.yml
