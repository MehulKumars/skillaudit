#!/bin/sh
# Run skillaudit from this folder without installing (macOS / Linux).
DIR=$(cd "$(dirname "$0")" && pwd)
PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m skillaudit "$@"
