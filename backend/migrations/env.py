"""Alembic environment — sync runner using asyncpg URL converted to sync."""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import all models so autogenerate detects them
from database import Base  # noqa: E402
import models  # noqa: E402, F401

target_metadata = Base.metadata


def get_url() -> str:
    # Convert asyncpg URL to sync psycopg2 URL for Alembic
    url = os.environ.get("DATABASE_URL", config.get_main_option("sqlalchemy.url", ""))
    return url.replace("postgresql+asyncpg://", "postgresql://")


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
