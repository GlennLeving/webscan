#!/usr/bin/env bash
# Start WebScan. Use --host 0.0.0.0 to reach the UI from other machines.
cd "$(dirname "$0")"
exec python3 webscan.py "$@"
