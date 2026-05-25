# Alembic Migrations — Status

**⚠️ Alembic is NOT currently wired for production use.**

The application uses `src/db/schema.sql` as the primary schema management path.
Alembic migration files exist for historical reference but cannot run against
a real database because:

1. `env.py` has `target_metadata = None` (no SQLAlchemy models wired)
2. `env.py` uses synchronous `engine_from_config` but the app uses asyncpg
3. The `sqlalchemy.url` in `alembic.ini` requires a `DATABASE_URL` env var that
   isn't set in the standard deployment flow

## For schema changes

Edit `src/db/schema.sql` directly, then apply with:

```bash
psql -f src/db/schema.sql
```

## To properly wire Alembic (future work)

1. Create SQLAlchemy models that mirror the schema
2. Switch `env.py` to `run_async_migrations` with async engine
3. Set `DATABASE_URL` in `.env` or `alembic.ini`
4. Use `alembic revision --autogenerate` for future changes