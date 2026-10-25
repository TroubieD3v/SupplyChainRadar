PY ?= python
VENV ?= .venv
BIN := $(VENV)/bin
ifeq ($(OS),Windows_NT)
BIN := $(VENV)/Scripts
endif

.PHONY: setup check backend frontend e2e benchmark examples docker smoke clean

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/python -m pip install -e "backend[dev]" types-jsonschema
	cd frontend && npm ci
	cd tests/e2e && npm ci

backend:
	$(BIN)/python -m ruff check backend
	$(BIN)/python -m ruff format --check backend
	$(BIN)/python -m mypy backend/src
	$(BIN)/python -m pytest backend/tests

frontend:
	cd frontend && npm run lint && npm run typecheck && npm test && npm run build

check: backend frontend

e2e: frontend
	cd tests/e2e && npx playwright test

benchmark:
	$(BIN)/python scripts/benchmark.py --write docs/benchmark-results.json

examples:
	$(BIN)/python scripts/generate_examples.py

docker:
	docker compose up --build -d

smoke:
	$(BIN)/python scripts/smoke.py http://127.0.0.1:8000

clean:
	rm -rf out .pytest_cache .mypy_cache .ruff_cache frontend/dist
