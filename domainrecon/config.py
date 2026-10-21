"""Where things live, and the settings from .env - loaded once, before any module reads them."""

from pathlib import Path

from dotenv import load_dotenv

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent              # the project folder: .env and runs/ live here
RUNS = ROOT / "runs"
TEMPLATES = PACKAGE / "templates"
STATIC = PACKAGE / "web" / "static"

load_dotenv(ROOT / ".env")
