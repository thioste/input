from fastapi import FastAPI, Depends, HTTPException, status
from sqlmodel import SQLModel, Field, Session, create_engine, select
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import smtplib
from email.mime.text import MIMEText
from typing import Optional
import random
import string

from models import engine, User, create_db

app = FastAPI()

# Secret Key for JWT
SECRET_KEY = "4686a5f3f2c54a712298ba363265b3996207a63b0c82997f1ad9ac1442914f80871f002e098a51e541f7e36e78600e55db1b4a39d9d950b9dd16f38aabf419559554036e77639b850528de6c785e38bb439b7195b9420ae586605e5035448800b6833dccf5b2805b85c486623094a055eb4b15418f442ececa38641f8d560646945ece19490bbb963854b76ca57ca953119422c62c0f70998cfc582f5cb6c7053c3c354393d205b03ab39ecf4901f7ae605214fc9f1cd32ca75671f2e2584f0ad8b98723b58ac81a5dc9bbe16043761c5e6f3e6ad60b6731bae729a4a83e205d07ac7f227f745c8c5ac598c5b527c9f52a41045cda210f7b1083552a79df56f6"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Utility Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_auth_code():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def send_email(to_email: str, auth_code: str):
    # Replace with actual SMTP settings
    sender_email = ""
    sender_password = ""
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    msg = MIMEText(f"Your authentication code: {auth_code}")
    msg["Subject"] = "Your Auth Code"
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send email")


# API Endpoints
@app.post("/register/")
def register_user(name: str, email: str, password: str, session: Session = Depends(lambda: Session(engine))):
    existing_user = session.exec(select(User).where(User.email == email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(password)
    auth_code = create_auth_code()
    new_user = User(name=name, email=email, hashed_password=hashed_password, auth_code=auth_code)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    send_email(email, auth_code)
    return {"message": "User registered. Check your email for authentication code."}

@app.post("/verify/")
def verify_user(email: str, auth_code: str, session: Session = Depends(lambda: Session(engine))):
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or user.auth_code != auth_code:
        raise HTTPException(status_code=400, detail="Invalid authentication code")

    user.is_active = True
    user.auth_code = None
    session.add(user)
    session.commit()
    return {"message": "User verified successfully"}

@app.post("/login/")
def login_user(email: str, password: str, session: Session = Depends(lambda: Session(engine))):
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User not verified")

    access_token = create_access_token(data={"sub": email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# Run this to create the database tables
create_db()