BINARY_NAME=$(shell basename `pwd`)
BUILD_OPTS=

build:
	@go build -o bin/$(BINARY_NAME) $(BUILD_OPTS) .

build-windows:
	@GOOS=windows GOARCH=amd64 go build -o bin/$(BINARY_NAME).exe $(BUILD_OPTS) .