# Local development shortcuts. Run `make` for the list.
# Everything here uses SQLite and DEBUG; the server uses `docker compose`.

export DJANGO_DEBUG := 1
MANAGE := uv run python manage.py

.DEFAULT_GOAL := help
.PHONY: help setup install migrate sync demo run test test-fast check shell \
        migrations staff reset clean up down logs

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: install migrate demo ## First run: install, migrate, demo data
	@printf "\nNow run: make run   then open http://127.0.0.1:8000\n"

install: ## Install Python dependencies (uv)
	uv sync

migrate: ## Apply database migrations
	$(MANAGE) migrate

sync: ## Load lab definitions from apps/labs/content into the database
	$(MANAGE) sync_labs

demo: ## Demo accounts (lecturer, ta, 2045001-3; password demo-pass-2026) + publish all labs
	$(MANAGE) seed_demo

run: ## Start the dev server on http://127.0.0.1:8000
	$(MANAGE) runserver

test: ## Run the full test suite
	$(MANAGE) test tests

test-fast: ## Re-run tests, stopping at the first failure
	$(MANAGE) test tests --failfast --keepdb

check: ## Django system checks + missing-migration check
	$(MANAGE) check
	$(MANAGE) makemigrations --check --dry-run

shell: ## Django shell
	$(MANAGE) shell

migrations: ## Create migrations after changing models
	$(MANAGE) makemigrations

staff: ## Create a staff account: make staff NAME=jagyemang ROLE=lecturer
	@test -n "$(NAME)" || (echo "usage: make staff NAME=<username> [ROLE=lecturer|ta]"; exit 1)
	$(MANAGE) create_staff $(NAME) --role $(or $(ROLE),ta)

reset: ## Delete the local database and start fresh with demo data
	rm -f db.sqlite3
	$(MAKE) migrate demo

clean: ## Remove caches and collected static files
	find . -name __pycache__ -type d -not -path './.venv/*' -exec rm -rf {} +
	rm -rf staticfiles

up: ## Docker: build and start the full stack (needs .env and deploy/ca/out)
	docker compose up -d --build

down: ## Docker: stop the stack
	docker compose down

logs: ## Docker: follow logs
	docker compose logs -f --tail=100
