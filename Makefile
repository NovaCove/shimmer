


.PHONY: build run-debug

build:
	@echo "Building the project..."
	@go build -o shimmer ./cmd/shimmer

run-debug: build
	@echo "Running the project in debug mode..."
	@./shimmer server --log-level=debug 
	@echo "Debug mode is running. Press Ctrl+C to stop."

dev: run-debug