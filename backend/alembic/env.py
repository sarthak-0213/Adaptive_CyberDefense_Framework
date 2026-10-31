import sys
import os
from logging.config import fileConfig

from sqlalchemy import pool
from alembic import context

# add your model's Database object to the python path here.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import settings
from app.models import Base
from app.core.database import engine

# this is the Alembic Config object, which provides access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = str(engine.url)
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "pyformat"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine

    # Validate that in production, migrations are not executing against SQLite
    is_render = bool(os.environ.get("RENDER"))
    is_prod_env = os.environ.get("ENVIRONMENT", "").lower() in ("production", "prod") or os.environ.get("ENV", "").lower() in ("production", "prod")
    dialect_name = engine.url.get_dialect().name

    safe_url = engine.url.render_as_string(hide_password=True)
    print(f"[Alembic] Running migrations against database: {safe_url} (dialect: {dialect_name})")

    if (is_render or is_prod_env) and dialect_name == "sqlite":
        raise RuntimeError(
            f"[Alembic] CRITICAL FAILURE: Cannot run production migrations against SQLite ({safe_url}). "
            "Production deployments require a reachable PostgreSQL database. "
            "Please verify that DATABASE_URL is set in Render environment variables."
        )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
