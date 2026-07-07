# Development helpers for the MTG manager services.
#
# Local config lives in the git-ignored root .env file. Recipes below source it
# into the environment before running, so the Go/Node apps just read os.Getenv
# as they do in production — nothing app-side depends on the .env file existing.

# Load .env into every recipe if it exists (does not override vars already set
# in your shell, matching godotenv/direnv behaviour).
ENV_FILE ?= .env.development
ifneq (,$(wildcard $(ENV_FILE)))
include $(ENV_FILE)
export
endif

.DEFAULT_GOAL := help

.PHONY: help run-auth run-genkeys db-up db-down db-logs env-check

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

run-auth: ## Run the auth service with .env loaded
	cd auth && go run ./cmd/server

run-genkeys: ## Run the auth service with .env loaded
	cd auth && go run ./cmd/genkeys

db-up: ## Start the Postgres container
	docker compose up -d postgres

db-down: ## Stop the Postgres container
	docker compose down

db-logs: ## Tail the Postgres container logs
	docker compose logs -f postgres

env-check: ## Confirm required vars are loaded (values not printed)
	@if [ -n "$$DATABASE_URL" ]; then echo "DATABASE_URL=set"; else echo "DATABASE_URL=MISSING"; fi
	@echo "PORT=$${PORT:-8080 (default)}"
