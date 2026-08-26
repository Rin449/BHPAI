# Database Migrations (Alembic)

This directory is intended for database migrations using Alembic.

To initialize Alembic migrations for BHPAI:
```bash
alembic init database/migrations
```

Then edit `alembic.ini` and `env.py` to import `Base` from `database.session` and `target_metadata = Base.metadata`.
