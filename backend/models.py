from typing import Optional
from sqlmodel import Field, SQLModel, Table, Column, Integer, String, DateTime, ForeignKey, create_engine, func
from datetime import datetime

from passlib.context import CryptContext

# Database setup
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, echo=True)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(unique=True, index=True)
    phone: str|None = Field(default=None)
    hashed_password: str
    is_active: bool = Field(default=False)
    auth_code: Optional[str] = None
    is_admin: bool = Field(default=False)
    photo: Optional[str] = None

    created_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False
        )
    )

    model_config = {"arbitrary_types_allowed": True}


def create_db():
    SQLModel.metadata.create_all(engine)
