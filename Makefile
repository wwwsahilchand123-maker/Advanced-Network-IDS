.PHONY: help install migrate admin dev test clean

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make migrate    - Run database migrations"
	@echo "  make admin      - Create admin user"
	@echo "  make dev        - Run development server"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean temporary files"

install:
	cd backend && pip install -r requirements.txt

install-dev:
	cd backend && pip install -r requirements-dev.txt

migrate:
	cd backend && alembic upgrade head

init-db:
	cd backend && python scripts/init_db.py

admin:
	cd backend && python scripts/create_admin.py

dev:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	cd backend && pytest

test-coverage:
	cd backend && pytest --cov=app --cov-report=html

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf backend/htmlcov
