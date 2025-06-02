# Makefile for Nitro Enclave Deployment

# Variables
DOCKER_IMAGE_NAME = enclave-app
DOCKER_TAG = latest
EIF_FILE = signer.eif
ENCLAVE_CID = 5
CPU_COUNT = 2
MEMORY = 512
VSOCK_PORT_SECRET_MANAGER = 50001
VSOCK_PORT_PRIVY = 50002
VSOCK_PORT_BACKEND = 50003
AWS_REGION = us-east-2
PRIVY_API_URL = api.privy.io
GITHUB_TOKEN = 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

# Log files
SECRETS_LOG = /var/log/vsock-secrets.log
PRIVY_LOG = /var/log/vsock-privy.log
PID_DIR = /tmp/nitro-enclave-pids
SECRETS_PID = $(PID_DIR)/secrets-proxy.pid
PRIVY_PID = $(PID_DIR)/privy-proxy.pid

.PHONY: help build-docker build-eif start-proxy stop-proxy deploy-enclave clean status logs

# Default target
help:
	@echo "Available targets:"
	@echo "  build-docker     - Build the Docker image"
	@echo "  build-eif        - Build the EIF file from Docker image"
	@echo "  deploy-enclave   - Full deployment (build + proxy + run enclave)"
	@echo "  clean           - Clean up Docker images and EIF files"
	@echo "  status          - Show enclave status"
	@echo "  logs            - Show enclave logs"
	@echo "  stop-enclave    - Stop running enclave"
	@echo ""
	@echo "Usage: make deploy-enclave"

# Build Docker image
build-docker:
	@echo "Building Docker image..."
	docker build --build-arg GITHUB_TOKEN="$(GITHUB_TOKEN)" -t $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) .
	@echo "Docker image built successfully"

# Build EIF file
build-eif: build-docker
	@echo "Building EIF file..."
	nitro-cli build-enclave --docker-uri $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) --output-file $(EIF_FILE)
	@echo "EIF file created: $(EIF_FILE)"

# Create PID directory
create-pid-dir:
	@mkdir -p $(PID_DIR)

# Deploy enclave (main target)
deploy-enclave: build-eif
	@echo "Deploying Nitro Enclave..."
	@echo "Stopping any existing enclaves..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@sleep 2
	@echo "Starting new enclave..."
	sudo nitro-cli run-enclave --cpu-count $(CPU_COUNT) --memory $(MEMORY) --enclave-cid $(ENCLAVE_CID) --eif-path $(EIF_FILE) --debug-mode
	@echo "Enclave deployment complete!"

# Runs docker
docker-run: build-docker 
	@echo "Starting enclave docker"
	sudo docker run enclave-app:latest

# Clean up
clean:
	@echo "Cleaning up..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@docker rmi $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) 2>/dev/null || true
	@rm -f $(EIF_FILE)
	@rm -rf $(PID_DIR)
	@echo "Cleanup complete"

# Show enclave status
status:
	@echo "Enclave Status:"
	@sudo nitro-cli describe-enclaves
	@echo ""
	@$(MAKE) proxy-status

# Show enclave logs
logs:
	@echo "Recent enclave logs:"
	@sudo ls -la /var/log/nitro_enclaves/ | tail -5
	@echo ""
	@echo "Latest error log:"
	@sudo tail -20 /var/log/nitro_enclaves/err*.log 2>/dev/null || echo "No error logs found"
	@echo ""
	@echo "Proxy logs:"
	@echo "--- Secrets Manager Proxy ---"
	@sudo tail -10 $(SECRETS_LOG) 2>/dev/null || echo "No secrets proxy logs found"
	@echo "--- Privy Proxy ---"
	@sudo tail -10 $(PRIVY_LOG) 2>/dev/null || echo "No privy proxy logs found"

# Show proxy logs only
proxy-logs:
	@echo "Secrets Manager Proxy Logs:"
	@sudo tail -20 $(SECRETS_LOG) 2>/dev/null || echo "No secrets proxy logs found"
	@echo ""
	@echo "Privy Proxy Logs:"
	@sudo tail -20 $(PRIVY_LOG) 2>/dev/null || echo "No privy proxy logs found"

# Stop enclave
stop-enclave:
	@echo "Stopping enclave..."
	@sudo nitro-cli terminate-enclave --all
	@echo "Enclave stopped"

# Connect to enclave console (requires manual enclave-id input)
console:
	@echo "Available enclaves:"
	@sudo nitro-cli describe-enclaves
	@echo ""
	@echo "To connect to console, run:"
	@echo "sudo nitro-cli console --enclave-id <enclave-id>"

# Restart deployment
restart: stop-enclave deploy-enclave


# Development target - run with console attached
dev-deploy: build-eif
	@echo "Deploying Nitro Enclave in development mode..."
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@sleep 2
	sudo nitro-cli run-enclave \
		--cpu-count $(CPU_COUNT) \
		--memory $(MEMORY) \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path $(EIF_FILE) \
		--debug-mode \
		--attach-console