.PHONY: all build clean linux windows darwin installer-windows

BINARY_NAME=rikugan
VERSION?=1.0.0
INSTALLER_DIR=installer/windows
DIST_DIR=dist

all: build

build:
	go build -ldflags "-s -w" -o $(BINARY_NAME) .

# Cross-compilation targets
linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o $(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o $(BINARY_NAME)-linux-arm64 .

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o $(BINARY_NAME)-windows-amd64.exe .

darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o $(BINARY_NAME)-darwin-arm64 .

all-platforms: linux windows darwin

# Windows installer package (creates a zip with exe + installer scripts)
installer-windows: windows
	@echo "Creating Windows installer package..."
	@mkdir -p $(DIST_DIR)
	@mkdir -p $(DIST_DIR)/windows-installer
	@cp $(BINARY_NAME)-windows-amd64.exe $(DIST_DIR)/windows-installer/rikugan.exe
	@cp $(INSTALLER_DIR)/install-agent.ps1 $(DIST_DIR)/windows-installer/
	@cp $(INSTALLER_DIR)/install.bat $(DIST_DIR)/windows-installer/
	@cp $(INSTALLER_DIR)/README.md $(DIST_DIR)/windows-installer/
	@cd $(DIST_DIR) && zip -r rikugan-$(VERSION)-windows-installer.zip windows-installer
	@rm -rf $(DIST_DIR)/windows-installer
	@echo "Created: $(DIST_DIR)/rikugan-$(VERSION)-windows-installer.zip"

# Create distribution packages for all platforms
dist: all-platforms installer-windows
	@mkdir -p $(DIST_DIR)
	@cp $(BINARY_NAME)-linux-amd64 $(DIST_DIR)/
	@cp $(BINARY_NAME)-linux-arm64 $(DIST_DIR)/
	@cp $(BINARY_NAME)-darwin-amd64 $(DIST_DIR)/
	@cp $(BINARY_NAME)-darwin-arm64 $(DIST_DIR)/
	@cp $(BINARY_NAME)-windows-amd64.exe $(DIST_DIR)/
	@echo "Distribution packages created in $(DIST_DIR)/"

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*
	rm -rf $(DIST_DIR)

# Development helpers
run-server:
	go run . -server

run-agent:
	@echo "Usage: make run-agent SERVER_URL=http://localhost:8080 TOKEN=your-token"
	go run . -agent -server-url $(SERVER_URL) -token $(TOKEN)

test:
	go test -v ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

fmt:
	go fmt ./...

vet:
	go vet ./...
