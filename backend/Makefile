.PHONY: help install migrate admin dev test clean demo

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make migrate    - Run database migrations"
	@echo "  make admin      - Create admin user"
	@echo "  make demo       - Generate demo data"
	@echo "  make dev        - Run development server"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean temporary files"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

migrate:
	alembic upgrade head

init-db:
	python scripts/init_db.py

admin:
	python scripts/create_admin.py

demo:
	python scripts/demo_mode.py

dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-sudo:
	sudo uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest

test-coverage:
	pytest --cov=app --cov-report=html

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf backend/htmlcov

setup:
	@echo "🚀 Setting up Advanced IDS..."
	make install
	make init-db
	make migrate
	make admin
	@echo "✅ Setup complete! Run 'make dev' to start"

setup-demo:
	@echo "🚀 Setting up Advanced IDS with demo data..."
	make install
	make init-db
	make migrate
	make admin
	make demo
	@echo "✅ Setup complete! Run 'make dev' to start"
