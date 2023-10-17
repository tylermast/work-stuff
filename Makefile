MAIN_PATH := ./cmd/main/main.go
BUILD_PATH := ./build
EXE_NAME := work_stuff
KEY := $(shell hexdump -vn32 -e'10/4 "%08X" 1 "\n"' /dev/urandom | sed 's/[ \t]*$$//')
# hexdump -vn32 -e'10/4 "%08X" 1 "\n"' /dev/urandom | sed 's/[ \t]*$//'

tidy:
	go mod tidy

build: tidy
	go build -o ${BUILD_PATH}/${EXE_NAME} ${MAIN_PATH}

run: build
	${BUILD_PATH}/${EXE_NAME} -key="${KEY}"
	
