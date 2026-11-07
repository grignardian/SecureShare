#!/usr/bin/env bash
# SecureShare Application Launcher
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "Starting SecureShare Desktop Application..."
python3 app.py
