# CLAUDE.md - HoneyOS Development Guide

## Project Overview
HoneyOS is a self-hosted network deception and intrusion detection system. It deploys honeypot services (SSH, HTTP, Telnet, FTP, MySQL) to catch attackers during lateral movement on local networks.

## Architecture
- **Backend**: Python 3.11+ / Flask / SQLAlchemy / SQLite — runs at port 7778
- **Frontend**: Next.js 14 / React 18 / Tailwind CSS / Zustand — runs at port 7777
- **Deployment**: Docker Compose (primary), Raspberry Pi image (secondary)

## Quick Start
```bash
make setup    # Copy .env.example to .env
make dev      # Start dev environment with Docker
make prod     # Start production environment
```

## Key Commands
```bash
make dev              # Development mode (with hot reload)
make prod             # Production mode (detached)
make stop             # Stop all services
make logs             # Tail all logs
make test-backend     # Run Python tests
make test-frontend    # Run frontend tests
make pi-build         # Build ARM64 images for Raspberry Pi
```

## Backend Development
- Entry point: `backend/app.py`
- API routes: `backend/api/` (Flask Blueprints)
- Database models: `backend/models/__init__.py`
- Services: `backend/services/`
- Protocol honeypots: `backend/services/protocols/`
- Run locally: `cd backend && pip install -r requirements.txt && python app.py`

## Frontend Development
- Entry point: `frontend/src/app/layout.tsx`
- Pages use Next.js App Router in `frontend/src/app/`
- API client: `frontend/src/lib/api.ts`
- State: `frontend/src/stores/useStore.ts` (Zustand)
- Run locally: `cd frontend && npm install && npm run dev`

## Database
- SQLite database at `/data/honeyos.db` (Docker) or `backend/honeyos.db` (local)
- Models defined with SQLAlchemy ORM
- Migrations in `database/migrations/`
- Tables auto-created on first run

## API Base URL
- Development: `http://localhost:7778`
- Docker internal: `http://backend:7778`
- All API routes prefixed with `/api/`
- Health check: `GET /health`

## Honeypot Ports (defaults)
- SSH: 2222
- HTTP: 8080
- Telnet: 2323
- FTP: 2121
- MySQL: 3307

## Code Conventions
- Python: type hints, snake_case, docstrings for public functions
- TypeScript: strict mode, interfaces for API responses
- Git: conventional commits (feat:, fix:, docs:, etc.)
- No authentication — this is a local-only deployment
