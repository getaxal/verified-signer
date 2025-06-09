# Makefile for Nitro Enclave Deployment

# Variables
DOCKER_IMAGE_NAME = verified-signer
DOCKER_TAG = latest
EIF_FILE = signer.eif
ENCLAVE_CID = 5
CPU_COUNT = 2
MEMORY = 512

# Log files
BUILD_LOG = ./logs/nitro-enclave-build.log
ENCLAVE_CONSOLE_LOG = ./logs/nitro-enclave-console.log
CONSOLE_PID_FILE = ./logs/console.pid

.PHONY: help build-docker build-eif deploy-enclave clean status logs stop-enclave

# Default target
help:
	@echo "Available targets:"
	@echo "  build-docker     - Build the Docker image"
	@echo "  build-eif        - Build the EIF file from Docker image"
	@echo "  deploy-enclave   - Full deployment (build + run enclave)"
	@echo "  deploy-with-console - Deploy and attach to console with logging"
	@echo "  console-log      - Connect to existing enclave console with logging"
	@echo "  console-bg       - Connect to enclave console in background"
	@echo "  stop-console-bg  - Stop background console logging"
	@echo "  clean           - Clean up Docker images and EIF files"
	@echo "  status          - Show enclave status"
	@echo "  logs            - Show enclave logs"
	@echo "  stop-enclave    - Stop running enclave"
	@echo "  view-build-log  - View build logs"
	@echo "  view-console-log - View console logs"
	@echo ""
	@echo "Usage: make deploy-with-console-bg"

# Initialize build log file with timestamp
init-build-log:
	@mkdir -p logs
	@echo "=== Nitro Enclave Build Log - $(shell date) ===" >> $(BUILD_LOG)
	@echo "" >> $(BUILD_LOG)

# Build Docker image (SSH-based) with logging
build-docker: init-build-log
	@echo "Building Docker image with SSH authentication..." | tee -a $(BUILD_LOG)
	docker build --ssh default -t $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) . 2>&1 | tee -a $(BUILD_LOG)
	@echo "Docker image built successfully" | tee -a $(BUILD_LOG)
	@echo "Build logs saved to: $(BUILD_LOG)"

# Build EIF file with logging
build-eif: build-docker
	@echo "Building EIF file..." | tee -a $(BUILD_LOG)
	sudo nitro-cli build-enclave --docker-uri $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) --output-file $(EIF_FILE) 2>&1 | tee -a $(BUILD_LOG)
	@echo "EIF file created: $(EIF_FILE)" | tee -a $(BUILD_LOG)
	@echo "Build logs saved to: $(BUILD_LOG)"

# Initialize console log file with timestamp
init-console-log:
	@mkdir -p logs
	@echo "=== Nitro Enclave Console Log - $(shell date) ===" >> $(ENCLAVE_CONSOLE_LOG)
	@echo "" >> $(ENCLAVE_CONSOLE_LOG)

# Runs docker with logging
docker-run: build-docker 
	@echo "Starting enclave docker" | tee -a $(BUILD_LOG)
	sudo docker run $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) 2>&1 | tee -a $(BUILD_LOG)

# Clean up
clean:
	@echo "Cleaning up..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@docker rmi $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) 2>/dev/null || true
	@rm -f $(EIF_FILE)
	@rm -f $(CONSOLE_PID_FILE)
	@echo "Cleanup complete"

# Show enclave status
status:
	@echo "Enclave Status:"
	@sudo nitro-cli describe-enclaves

# Show console logging status
console-status:
	@if [ -f $(CONSOLE_PID_FILE) ]; then \
		PID=$$(cat $(CONSOLE_PID_FILE)); \
		if ps -p $$PID > /dev/null 2>&1; then \
			echo "Console logging is running in background (PID: $$PID)"; \
		else \
			echo "Console logging PID file exists but process is not running"; \
			rm -f $(CONSOLE_PID_FILE); \
		fi; \
	else \
		echo "Console logging is not running in background"; \
	fi

# Show enclave logs
logs:
	@echo "Recent enclave logs:"
	@sudo ls -la /var/log/nitro_enclaves/ | tail -5
	@echo ""
	@echo "Latest error log:"
	@sudo tail -20 /var/log/nitro_enclaves/err*.log 2>/dev/null || echo "No error logs found"

# Stop enclave
stop-enclave:
	@echo "Stopping enclave..."
	@sudo nitro-cli terminate-enclave --all
	@echo "Enclave stopped"

# Connect to enclave console and log output
console:
	@echo "Available enclaves:"
	@sudo nitro-cli describe-enclaves
	@echo ""
	@echo "To connect to console with logging, use: make console-log ENCLAVE_ID=<enclave-id>"

# Connect to enclave console with logging (foreground)
console-log: init-console-log
	@if [ -z "$(ENCLAVE_ID)" ]; then \
		echo "Error: ENCLAVE_ID not specified. Usage: make console-log ENCLAVE_ID=<enclave-id>"; \
		echo "Available enclaves:"; \
		sudo nitro-cli describe-enclaves; \
		exit 1; \
	fi
	@echo "Connecting to enclave console and logging to $(ENCLAVE_CONSOLE_LOG)..."
	@echo "Press Ctrl+C to disconnect from console"
	sudo nitro-cli console --enclave-id $(ENCLAVE_ID) 2>&1 | tee -a $(ENCLAVE_CONSOLE_LOG)

# Connect to enclave console with logging (background)
console-bg: init-console-log
	@if [ -z "$(ENCLAVE_ID)" ]; then \
		echo "Error: ENCLAVE_ID not specified. Usage: make console-bg ENCLAVE_ID=<enclave-id>"; \
		echo "Available enclaves:"; \
		sudo nitro-cli describe-enclaves; \
		exit 1; \
	fi
	@if [ -f $(CONSOLE_PID_FILE) ]; then \
		echo "Console logging is already running. Use 'make stop-console-bg' to stop it first."; \
		exit 1; \
	fi
	@echo "Starting console logging in background..."
	@echo "Logs will be written to: $(ENCLAVE_CONSOLE_LOG)"
	@nohup sudo nitro-cli console --enclave-id $(ENCLAVE_ID) >> $(ENCLAVE_CONSOLE_LOG) 2>&1 & echo $$! > $(CONSOLE_PID_FILE)
	@echo "Console logging started in background (PID: $$(cat $(CONSOLE_PID_FILE)))"
	@echo "Use 'make tail-console-log' to follow the logs"
	@echo "Use 'make stop-console-bg' to stop background logging"

# Stop background console logging
stop-console-bg:
	@if [ -f $(CONSOLE_PID_FILE) ]; then \
		PID=$$(cat $(CONSOLE_PID_FILE)); \
		if ps -p $$PID > /dev/null 2>&1; then \
			echo "Stopping background console logging (PID: $$PID)..."; \
			sudo kill $$PID; \
			rm -f $(CONSOLE_PID_FILE); \
			echo "Background console logging stopped"; \
		else \
			echo "Console logging process not found, cleaning up PID file"; \
			rm -f $(CONSOLE_PID_FILE); \
		fi; \
	else \
		echo "No background console logging is running"; \
	fi

# Start enclave with console logging (foreground)
deploy-with-console: build-eif init-console-log
	@echo "Deploying Nitro Enclave with console logging..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@sleep 2
	@echo "Starting enclave and connecting to console..."
	@echo "Console output will be logged to $(ENCLAVE_CONSOLE_LOG)"
	@echo "Press Ctrl+C to disconnect from console"
	sudo nitro-cli run-enclave \
		--cpu-count $(CPU_COUNT) \
		--memory $(MEMORY) \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path $(EIF_FILE) \
		--debug-mode \
		--attach-console 2>&1 | tee -a $(ENCLAVE_CONSOLE_LOG)

# Start enclave with console logging (background)
deploy-with-console-bg: build-eif init-console-log
	@echo "Deploying Nitro Enclave with background console logging..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@sleep 2
	@if [ -f $(CONSOLE_PID_FILE) ]; then \
		echo "Console logging is already running. Use 'make stop-console-bg' to stop it first."; \
		exit 1; \
	fi
	@echo "Starting enclave with background console logging..."
	@echo "Console output will be logged to $(ENCLAVE_CONSOLE_LOG)"
	@nohup sudo nitro-cli run-enclave \
		--cpu-count $(CPU_COUNT) \
		--memory $(MEMORY) \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path $(EIF_FILE) \
		--debug-mode \
		--attach-console >> $(ENCLAVE_CONSOLE_LOG) 2>&1 & echo $$! > $(CONSOLE_PID_FILE)
	@echo "Enclave started with background console logging (PID: $$(cat $(CONSOLE_PID_FILE)))"
	@echo "Use 'make tail-console-log' to follow the logs"
	@echo "Use 'make console-status' to check status"
	@echo "Use 'make stop-console-bg' to stop background logging"

# Development target - run with console attached and logged (background)
dev-deploy-bg: init-console-log build-eif
	@echo "Deploying Nitro Enclave in development mode with background console logging..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@sleep 2
	@if [ -f $(CONSOLE_PID_FILE) ]; then \
		echo "Console logging is already running. Use 'make stop-console-bg' to stop it first."; \
		exit 1; \
	fi
	@echo "Console output will be logged to $(ENCLAVE_CONSOLE_LOG)"
	@nohup sudo nitro-cli run-enclave \
		--cpu-count $(CPU_COUNT) \
		--memory $(MEMORY) \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path $(EIF_FILE) \
		--debug-mode \
		--attach-console >> $(ENCLAVE_CONSOLE_LOG) 2>&1 & echo $$! > $(CONSOLE_PID_FILE)
	@echo "Development enclave started with background console logging (PID: $$(cat $(CONSOLE_PID_FILE)))"
	@echo "Use 'make tail-console-log' to follow the logs"

# Development target - run with console attached and logged (foreground)
dev-deploy: init-console-log build-eif
	@echo "Deploying Nitro Enclave in development mode with console logging..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@sleep 2
	@echo "Console output will be logged to $(ENCLAVE_CONSOLE_LOG)"
	@echo "Press Ctrl+C to disconnect from console"
	sudo nitro-cli run-enclave \
		--cpu-count $(CPU_COUNT) \
		--memory $(MEMORY) \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path $(EIF_FILE) \
		--debug-mode \
		--attach-console 2>&1 | tee -a $(ENCLAVE_CONSOLE_LOG)

restart: stop-enclave deploy-enclave

# Check SSH connectivity to GitHub
check-ssh:
	@echo "Testing SSH connection to GitHub..."
	ssh -T git@github.com || echo "SSH test complete (exit code above is normal for successful auth)"

# View the build log file
view-build-log:
	@echo "Displaying build log:"
	@cat $(BUILD_LOG)

# Tail the build log file (follow new entries)
tail-build-log:
	@echo "Following build log (Ctrl+C to exit):"
	@tail -f $(BUILD_LOG)

# Clear the build log file
clear-build-log:
	@echo "Clearing build log..."
	@> $(BUILD_LOG)
	@echo "Build log file cleared: $(BUILD_LOG)"

# View the console log file
view-console-log:
	@echo "Displaying console log:"
	@cat $(ENCLAVE_CONSOLE_LOG)

# Tail the console log file (follow new entries)
tail-console-log:
	@echo "Following console log (Ctrl+C to exit):"
	@tail -f $(ENCLAVE_CONSOLE_LOG)

# Clear the console log file
clear-console-log:
	@echo "Clearing console log..."
	@> $(ENCLAVE_CONSOLE_LOG)
	@echo "Console log file cleared: $(ENCLAVE_CONSOLE_LOG)"