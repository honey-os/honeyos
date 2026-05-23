.PHONY: help setup dev prod stop clean logs status build test

# Default target
help: ## Show this help message
	@echo "HoneyOS - Network Deception & Intrusion Detection System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Initial project setup - copy env file
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example - edit it with your settings"; \
	else \
		echo ".env already exists"; \
	fi

build: ## Build all Docker images
	docker compose build

dev: setup ## Start development environment
	docker compose -f docker-compose.dev.yml up --build

dev-detached: setup ## Start development environment (detached)
	docker compose -f docker-compose.dev.yml up --build -d

prod: setup ## Start production environment
	docker compose up --build -d

stop: ## Stop all services
	docker compose down
	docker compose -f docker-compose.dev.yml down

clean: ## Stop all services and remove volumes
	docker compose down -v
	docker compose -f docker-compose.dev.yml down -v

logs: ## Tail logs from all services
	docker compose logs -f

logs-backend: ## Tail backend logs
	docker compose logs -f backend

logs-frontend: ## Tail frontend logs
	docker compose logs -f frontend

status: ## Show status of all services
	docker compose ps

test-backend: ## Run backend tests
	cd backend && python -m pytest tests/ -v

test-frontend: ## Run frontend tests
	cd frontend && npm test

test: test-backend test-frontend ## Run all tests

backend-shell: ## Open shell in backend container
	docker compose exec backend /bin/bash

frontend-shell: ## Open shell in frontend container
	docker compose exec frontend /bin/sh

db-backup: ## Backup SQLite database
	@mkdir -p backups
	docker compose exec backend cp /data/honeyos.db /data/honeyos-backup-$$(date +%Y%m%d_%H%M%S).db
	@echo "Database backed up"

pi-build: ## Build ARM64 images for Raspberry Pi
	docker buildx build --platform linux/arm64 -t honeyos-backend:pi ./backend
	docker buildx build --platform linux/arm64 -t honeyos-frontend:pi ./frontend
	@echo "Raspberry Pi images built"
