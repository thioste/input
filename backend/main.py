from fastapi import FastAPI, Form, UploadFile, File, Depends, HTTPException, status
from sqlmodel import SQLModel, Field, Session, create_engine, select
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import smtplib
from email.mime.text import MIMEText
from typing import Optional, Annotated
import random
import string
from dotenv import load_dotenv
import os
from pathlib import Path
import shutil

from models import engine, User, create_db

load_dotenv()

app = FastAPI()

# Secret Key for JWT
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

#Files
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")
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
def register_user(name: str = Annotated[str, Form()],
                  email: str = Annotated[str, Form()],
                  password: str = Annotated[str, Form()],
                  profile_photo: UploadFile = File(...),
                  session: Session = Depends(lambda: Session(engine))):
    
    existing_user = session.exec(select(User).where(User.email == email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    file_location = f"{UPLOAD_FOLDER}/{profile_photo.filename}"

    with open(file_location, "wb") as f:
        f.write(profile_photo.file.read())

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