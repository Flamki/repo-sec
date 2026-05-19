"""Vercel FastAPI entrypoint.

This keeps the existing backend layout intact by adding the `backend/`
directory to `sys.path` and re-exporting the FastAPI `app`.
"""

from pathlib import Path
import sys


BACKEND_DIR = (Path(__file__).resolve().parent.parent / "backend").resolve()
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import app  # noqa: E402,F401
