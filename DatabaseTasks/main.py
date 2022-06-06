from email.policy import default
from requests import Session
from sqlalchemy import (FLOAT, Column, Float, ForeignKey, Integer, String,
                        create_engine, Identity)
from sqlalchemy.orm import declarative_base, sessionmaker
import os
from dotenv import load_dotenv
load_dotenv()


db_url = os.environ.get('DATABASE_URL')

engine = create_engine(db_url, echo=True)

Session = sessionmaker()

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, Identity(start=42, cycle=True), primary_key=True)
    full_name = Column(String(100))
    user_name = Column(String(100), unique=True)
    password = Column(String(100))

    def __repr__(self):
        return f"username = {self.name}"


class Product(Base):
    __tablename__ = 'products'

    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    price = Column(Float, default=0.0)
    category = Column(String(100))
    description = Column(String(500), nullable=False)
    image = Column(String(500))


class Cart(Base):
    __tablename__ = "cart"
    userId = Column(Integer, ForeignKey("users.id"), primary_key=True)
    productId = Column(Integer, ForeignKey("products.id"), primary_key=True)
    quantity = Column(Integer, default=1)
