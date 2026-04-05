import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.db.models import Base

# DB uses SQLite for local simplicity and ease of setup
DATABASE_FILE = os.environ.get("DATABASE_FILE", "epidemic_runtime.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///./{DATABASE_FILE}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
