.PHONY: install test run build docker-build docker-run clean lint

# ─── Local Development ──────────────────────────────────────────────────────

install:
	pip install -r requirements.txt
	pip install pytest pytest-asyncio pyyaml

test:
	python -m pytest tests/ -v --tb=short

test-coverage:
	python -m pytest tests/ -v --tb=short --cov=security --cov-report=term-missing

run:
	python app.py

lint:
	python -m pip install ruff
	python -m ruff check security/ tests/ app.py

# ─── Docker ─────────────────────────────────────────────────────────────────

build:
	docker build -t shieldllm .

docker-build: build

docker-run:
	docker run -d --name shieldllm -p 8080:8080 shieldllm

docker-stop:
	docker stop shieldllm 2>/dev/null; docker rm shieldllm 2>/dev/null

docker-logs:
	docker logs -f shieldllm

docker-shell:
	docker exec -it shieldllm sh

# ─── CI / Cleanup ───────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache .coverage

distclean: clean
	docker rmi shieldllm 2>/dev/null; true

# ─── Help ────────────────────────────────────────────────────────────────────

help:
	@echo "ShieldLLM Makefile"
	@echo "  make install     — install dependencies"
	@echo "  make test        — run test suite"
	@echo "  make run         — start the proxy locally"
	@echo "  make build       — build Docker image"
	@echo "  make docker-run  — run Docker container"
	@echo "  make lint        — ruff linting"
	@echo "  make clean       — remove cache files"
