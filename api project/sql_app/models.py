from typing import List
from sqlalchemy import Column, Integer, String, Enum
from sql_app.database import Base


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True)
    email = Column(String(50), unique=True)
    hash_password = Column(String(50))
    role = Column(Enum('User', 'Admin'), default='User')
    permissions: list[str] = ['User:read', 'Admin:read', 'Admin:create', 'Admin:update', 'Admin:delete']
