#!/bin/sh
set -e

# Start backend (gunicorn) in background
cd /app/backend
/app/venv/bin/gunicorn --bind 0.0.0.0:7778 --worker-class gthread \
    --workers 1 --threads 4 --timeout 120 --access-logfile - app:app &

# Start frontend (Next.js standalone) in foreground
cd /app/frontend
HOSTNAME=0.0.0.0 PORT=7777 exec node server.js
