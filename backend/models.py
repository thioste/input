from typing import Optional
from sqlmodel import Field, SQLModel, Table, Column, Integer, String, DateTime, ForeignKey, create_engine

from passlib.context import CryptContext

# Database setup
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, echo=True)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = Field(default=False)
    auth_code: Optional[str] = None

def create_db():
    SQLModel.metadata.create_all(engine)