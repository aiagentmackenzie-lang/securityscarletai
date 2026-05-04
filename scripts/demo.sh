#!/bin/bash
set -e

echo "🚀 Starting SecurityScarletAI demo..."
echo ""

# Start PostgreSQL
echo "📦 Starting PostgreSQL..."
docker-compose up -d

echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# Install dependencies
echo "📦 Installing dependencies..."
poetry install

# Run migrations
echo "🗄️ Running database migrations..."
poetry run alembic upgrade head

# Seed demo data
echo "🌱 Seeding demo data..."
poetry run python scripts/seed_demo_data.py

# Start API
echo "✅ Starting API on http://localhost:8000"
poetry run uvicorn src.api.main:app --port 8000 &
API_PID=$!
sleep 3

# Start Dashboard
echo "✅ Starting Dashboard on http://localhost:8501"
poetry run streamlit run dashboard/main.py --server.port 8501 &
DASH_PID=$!

echo ""
echo "🟢 SecurityScarletAI is running!"
echo ""
echo "   API:        http://localhost:8000/api/docs"
echo "   Dashboard:  http://localhost:8501"
echo "   Health:     http://localhost:8000/api/v1/health"
echo ""
echo "   Press Ctrl+C to stop all services"
echo ""

# Wait for interrupt
wait