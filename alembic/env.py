import asyncio
from logging.config import fileConfig

from sqlalchemy.ext.asyncio import async_engine_from_config, AsyncEngine
from sqlalchemy import pool
from alembic import context

import sys
from os.path import abspath, dirname

from src.core.config import settings
from src.db.database import Base

# Добавляем путь к проекту (если запускаем Alembic отдельно)
sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

# Alembic Config
config = context.config
fileConfig(config.config_file_name)

# Устанавливаем URL подключения к БД (из settings)
config.set_main_option("sqlalchemy.url", settings.db.database_url_async)

# Метаданные для автогенерации миграций
target_metadata = Base.metadata
from src.users.models import *

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable: AsyncEngine = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.begin() as connection:
        await connection.run_sync(
            lambda sync_conn: context.configure(
                connection=sync_conn,
                target_metadata=target_metadata,
            )
        )

        await connection.run_sync(lambda _: context.run_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())