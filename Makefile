
_UPX_ENV ?= --no-env
_UPX ?= $(shell which upx)

ifneq ($(UPX),)
_UPX := $(shell [ -f $(UPX) ] && echo $(UPX) || echo $(UPX)/upx)
endif

ifneq ($(_UPX),)
_UPX := $(shell [ -x $(_UPX) ] && echo $(_UPX) || which upx)
endif

ifeq ($(UPX_FAST),)
_UPX_ENV += --ultra-brute -9
else
_UPX_ENV += -1
endif

.PHONY: all
all: build

.PHONY: build
build: init fmt socks5forward

.PHONY: release
release: init fmt release_socks5forward

.PHONY: release_build
release_build:
ifneq ($(BINNAME),)
	@rm -rf release/$(BINNAME)
ifneq ($(_UPX),)
	@$(_UPX) $(_UPX_ENV) bin/$(BINNAME) -o release/$(BINNAME)
else
	@echo -e "\033[32;1m### \033[31;1mNo UPX be found, Uncompressed provided!\033[32;1m ###\033[0m"
	@cp -raf bin/$(BINNAME) release/$(BINNAME)
endif
endif

.PHONY: init
init:
	@mkdir -p bin release

.PHONY: fmt
fmt:
	@go fmt ./...

.PHONY: socks5forward
socks5forward:
	@go build -ldflags "-w -s" -o bin/$@

.PHONY: release_socks5forward
release_socks5forward: socks5forward
	@BINNAME=$^ make -C . release_build

.PHONY: clean
clean:
	@go clean -i -n -x -cache
	@rm -rf bin go.sum

.PHONY: distclean
distclean:
	@go clean -i -n -x --modcache
	@rm -rf bin go.sum release
