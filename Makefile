.PHONY: dev test seed build docker-up docker-down

dev:
	@echo "Starting API Sentinel development services..."
	@bash start_dev.sh

seed:
	@echo "Seeding database with demo data..."
	cd backend && python -m app.seed

test:
	@echo "Running backend test suite..."
	cd backend && pytest -v

docker-up:
	@echo "Starting full platform via Docker Compose..."
	docker compose up --build -d

docker-down:
	@echo "Stopping Docker containers..."
	docker compose down
