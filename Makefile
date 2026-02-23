APP := hostup
DIST_DIR := dist

GO ?= go
GOCACHE ?= $(CURDIR)/.gocache
GOTMPDIR ?= $(CURDIR)/.gotmp
export GOCACHE
export GOTMPDIR

.PHONY: all make_dirs nix test clean

all: $(APP)

make_dirs:
	@mkdir -p "$(GOCACHE)" "$(GOTMPDIR)"

dist_dir:
	@mkdir -p "$(DIST_DIR)"

$(APP): make_dirs
	$(GO) build -o "$(APP)" .

nix: make_dirs dist_dir
	GOOS=darwin GOARCH=amd64 $(GO) build -o "$(DIST_DIR)/$(APP)-mac-x64" .
	GOOS=darwin GOARCH=arm64 $(GO) build -o "$(DIST_DIR)/$(APP)-mac-arm64" .
	GOOS=linux GOARCH=amd64 $(GO) build -o "$(DIST_DIR)/$(APP)-Linux-x64" .
	GOOS=linux GOARCH=arm64 $(GO) build -o "$(DIST_DIR)/$(APP)-Linux-arm64" .

test:
	./smoke-hostup.zsh

clean:
	rm -f "$(APP)"
	rm -rf "$(DIST_DIR)"
	rm -rf "$(GOCACHE)" "$(GOTMPDIR)"
