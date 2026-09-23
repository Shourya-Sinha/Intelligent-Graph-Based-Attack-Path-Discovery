"""
Free DB session — SQLite for local dev, Postgres for prod (both free).
Currently uses InMemoryStore for zero-config demo, but this file shows advanced structure.
"""
# from sqlalchemy import create_engine
# from sqlalchemy.orm import sessionmaker
# SQLALCHEMY_DATABASE_URL = "sqlite:///./free.db"  # free, local
# engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# InMemoryStore is used for now — no DB required to run (free)
