import os
import logging
from urllib.parse import urlsplit, urlunsplit
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

logger = logging.getLogger("app")


def sanitize_db_url(url: str) -> str:
    """Mask credentials in database URL for safe logging."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        if parts.password:
            netloc = f"{parts.username or ''}:****@{parts.hostname or ''}"
            if parts.port:
                netloc += f":{parts.port}"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        pass
    return "database://***:***@***"


# Determine target database URL
db_url = settings.DATABASE_URL
if os.environ.get("DATABASE_URL"):
    db_url = os.environ.get("DATABASE_URL").strip()

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

is_render = bool(os.environ.get("RENDER"))
is_prod_env = os.environ.get("ENVIRONMENT", "").lower() in ("production", "prod") or os.environ.get("ENV", "").lower() in ("production", "prod")
is_production = is_render or is_prod_env
is_testing = bool(os.environ.get("TESTING") or os.environ.get("PYTEST_CURRENT_TEST"))

connect_args = {}
engine = None

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(
        db_url,
        connect_args=connect_args,
        pool_pre_ping=True
    )
    logger.info(f"Using SQLite database engine: {db_url}")
else:
    # Target is PostgreSQL
    pg_connect_args = {
        "connect_timeout": 10,
    }

    sanitized_url = sanitize_db_url(db_url)

    try:
        temp_engine = create_engine(
            db_url,
            connect_args=pg_connect_args,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            pool_recycle=300
        )
        # Verify connection immediately on startup
        with temp_engine.connect() as conn:
            pass
        engine = temp_engine
        logger.info(f"Successfully connected to PostgreSQL database at {sanitized_url}.")
    except Exception as e:
        err_msg = str(e)
        logger.error(f"PostgreSQL connection to '{sanitized_url}' failed: {err_msg}")

        # Enforce strict production / configured policy: DO NOT silently fall back to SQLite
        if is_production or os.environ.get("DATABASE_URL"):
            error_details = (
                f"\n================================================================================\n"
                f"CRITICAL DATABASE CONNECTION FAILURE: Application startup aborted.\n"
                f"================================================================================\n"
                f"Failed to establish connection to PostgreSQL database:\n"
                f"  Target URL: {sanitized_url}\n"
                f"  Underlying Error: {err_msg}\n\n"
                f"DIAGNOSIS & RESOLUTION STEPS FOR RENDER DEPLOYMENTS:\n"
                f"1. Hostname Resolution Error ('could not translate host name' / socket.gaierror):\n"
                f"   - On Render, Internal Database URLs (e.g. 'dpg-xxxx-a:5432') ONLY resolve\n"
                f"     between services in the SAME Render Region and Account.\n"
                f"   - If your Web Service and Database are in different regions, or if accessing\n"
                f"     externally, you MUST use Render's External Database URL:\n"
                f"     (e.g., 'dpg-xxxx-a.oregon-postgres.render.com:5432').\n"
                f"2. Database URL Configuration:\n"
                f"   - Verify that 'DATABASE_URL' is defined in your Render Environment settings.\n"
                f"   - If the default host 'db:5432' appears, your Web Service does not have\n"
                f"     DATABASE_URL set, or it is defaulting to local Docker Compose.\n"
                f"3. URL Scheme:\n"
                f"   - Ensure the connection starts with 'postgresql://' (not 'postgres://').\n"
                f"4. Render PostgreSQL Suspended / Free-tier Spin Down:\n"
                f"   - Ensure your PostgreSQL database status in Render dashboard is 'Available'.\n"
                f"================================================================================\n"
            )
            logger.critical(error_details)
            raise RuntimeError(error_details) from e
        else:
            # Local development fallback when not running in production and no explicit DATABASE_URL was configured
            logger.warning(
                f"Local development mode detected: PostgreSQL unavailable at '{sanitized_url}'. "
                f"Falling back to local SQLite database (sqlite:///./app.db)."
            )
            db_url = "sqlite:///./app.db"
            engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                pool_pre_ping=True
            )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
