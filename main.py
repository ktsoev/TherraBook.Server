from fastapi import FastAPI, HTTPException, Depends, status, Header, Request, Query
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Optional
from starlette.responses import Response
from sqlalchemy import create_engine, Column, Integer, String, Boolean, BigInteger, Enum, Text, TIMESTAMP, func
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta, timezone
import enum
from telegram import Bot
import sqlalchemy.exc
import base64
import requests
import os
import jwt
import json
import hmac
import hashlib
import time
import logging
from dotenv import load_dotenv
from telegram_utils import send_telegram_message

# Загрузка переменных окружения
load_dotenv()

# Проверка обязательных переменных окружения
required_env_vars = [
    "SECRET_KEY",
    "HMAC_SECRET",
    "HMAC_SECRET_WITHDRAW",
    "BOT_TOKEN",
    "CHAT_ID",
    "DATABASE_URL"
]

missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise EnvironmentError(f"Отсутствуют обязательные переменные окружения: {', '.join(missing_vars)}")

CONFIG_FILE = os.getenv("CONFIG_FILE", "./confs/config.json")

LOGS_FILE = os.getenv("LOGS_FILE", "./logs/logs.log")

SECRET_KEY = os.getenv("SECRET_KEY")
HMAC_SECRET = os.getenv("HMAC_SECRET")
HMAC_SECRET_WITHDRAW = os.getenv("HMAC_SECRET_WITHDRAW")

ALGORITHM = "HS256"

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "24"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL,
    pool_size=10,  # Размер пула
    max_overflow=20,  # Допустимый "оверфлоу" (резервные соединения)
    pool_timeout=30,  # Время ожидания свободного соединения (сек)
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
used_nonces = set()

bot = Bot(token=BOT_TOKEN)

logging.basicConfig(
    filename=LOGS_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

class WithdrawalStatus(enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    REJECTED = "rejected"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), unique=True, nullable=False, index=True)
    balance = Column(Integer, default=0)
    total_earned = Column(Integer, default=0)
    total_withdrawn = Column(Integer, default=0)
    ads_watched = Column(Integer, default=0)
    is_banned = Column(Boolean, default=False)
    last_active_at = Column(TIMESTAMP, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


class Withdrawal(Base):
    __tablename__ = "withdrawals"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(String(255), nullable=False, index=True)
    amount = Column(Integer, nullable=False)
    status = Column(
        Enum(WithdrawalStatus, native_enum=False, length=20),
        default=WithdrawalStatus.PENDING,
        nullable=False
    )
    payment_method = Column(String(50), nullable=True)
    payment_details = Column(Text, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    completed_at = Column(TIMESTAMP, nullable=True)

class TransactionRequest(BaseModel):
    price: int
    amount: int
    pay_method: str
    address: str

Base.metadata.create_all(bind=engine)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[str] = None

def load_config():
    with open(CONFIG_FILE, 'r') as file:
        return json.load(file)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Header(...)) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id or user_id == "":
            raise HTTPException(status_code=401, detail="error")
        return TokenData(user_id=user_id)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="error")
    except Exception:
        raise HTTPException(status_code=401, detail="error")

def verify_hmac(data: str, received_signature: str, secret: str):
    signature = hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, received_signature):
        raise HTTPException(status_code=401, detail="error")

def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0]
    return request.client.host

def decrypt(encrypted_data: str) -> str:
    decrypted_data = base64.b64decode(encrypted_data)
    return decrypted_data.decode('utf-8')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_or_create_user(db: Session, user_id: str):
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            user = User(
                user_id=user_id,
                balance=0,
                total_earned=0,
                total_withdrawn=0,
                ads_watched=0,
                is_banned=False,
                last_active_at=datetime.now(timezone.utc)
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            # Обновляем last_active_at при каждом обращении
            user.last_active_at = datetime.now(timezone.utc)
            db.commit()
        return user
    except sqlalchemy.exc.TimeoutError:
        logger.error("SQL timeout in get_or_create_user, restarting service")
        time.sleep(2)
        os.system("systemctl restart therrabook.service")
        exit(1)

def get_user(db: Session, user_id: str):
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            return None
        return user
    except sqlalchemy.exc.TimeoutError:
        logger.error("SQL timeout in get_user, restarting service")
        time.sleep(2)
        os.system("systemctl restart therrabook.service")
        exit(1) 

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# CORS
origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://api.therrabook.ru",
    "https://api.therrabook.ru",
]

class CORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Логируем CORS запросы
        if request.method == "OPTIONS":
            logger.info(f"CORS preflight request: {request.url} from {request.headers.get('origin', 'unknown')}")
        
        response = await call_next(request)
        
        # CORS заголовки для всех ответов
        origin = request.headers.get("origin")
        if origin in origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        return response

app.add_middleware(CORSMiddleware)

@app.options("/{path:path}")
async def options_handler(path: str):
    return JSONResponse(
        status_code=200,
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "86400"
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    try:
        logger.error(f"HTTPException: {exc.detail}, Status: {exc.status_code}")
        logger.error(f"Request URL: {request.url}, Headers: {request.headers}")
        logger.error(f"Exception type: {type(exc).__name__}")
        logger.error(f"Exception args: {exc.args}")
        if hasattr(exc, '__cause__') and exc.__cause__:
            logger.error(f"Caused by: {type(exc.__cause__).__name__}: {str(exc.__cause__)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
    except Exception as e:
        logger.error(f"Error in http_exception_handler: {str(e)}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail if exc.detail else "Internal server error"},
        headers={
            "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
            "Access-Control-Allow-Credentials": "true"
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    try:
        logger.error(f"Validation Error: {exc.errors()}")
        logger.error(f"Request URL: {request.url}, Headers: {request.headers}")
    except Exception as e:
        logger.error(f"Error in validation_exception_handler: {str(e)}")
    return JSONResponse(
        status_code=400,
        content={"detail": exc.errors()},
        headers={
            "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
            "Access-Control-Allow-Credentials": "true"
        }
    )

@app.post("/auth/")
async def auth(user_id: str,
               db: Session = Depends(get_db),
               signature: str = Header(...)):
    verify_hmac(user_id, signature, HMAC_SECRET)
    user = get_or_create_user(db, user_id)
    
    # Проверяем, не забанен ли пользователь
    if user.is_banned:
        raise HTTPException(status_code=403, detail="User is banned")
    
    access_token = create_access_token(data={"sub": user.user_id})
    config = load_config()
    return {
        "id": user.id,
        "balance": user.balance,
        "access_token": access_token,
        "social_links": config["urls"]["social"],
        "withdraw_url": config["urls"]["withdraw"],
        "version": config["version"]
    }

@app.post("/login/")
async def login(user_id: str,
                db: Session = Depends(get_db),
                signature: str = Header(...)):
    verify_hmac(user_id, signature, HMAC_SECRET_WITHDRAW)
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="error")
    
    # Проверяем, не забанен ли пользователь
    if user.is_banned:
        raise HTTPException(status_code=403, detail="User is banned")
    
    # Обновляем last_active_at
    user.last_active_at = datetime.now(timezone.utc)
    db.commit()
    
    access_token = create_access_token(data={"sub": user.user_id})
    config = load_config()
    return {
        "id": user.id,
        "balance": user.balance,
        "access_token": access_token,
        "social_links": config["urls"]["social"],
        "withdraw_url": config["urls"]["withdraw"],
        "version": config["version"]
    }

@app.post("/add/")
async def add(user_data: TokenData = Depends(verify_token),
              db: Session = Depends(get_db),
              signature: str = Header(...),
              client_ip: str = Depends(get_client_ip),
              timestamp: int = Header(...)):
    try:
        if abs(int(time.time()) - timestamp) > REQUEST_TIMEOUT:
            raise HTTPException(status_code=400, detail="error")
        verify_hmac(f"{user_data.user_id}:{timestamp}", signature, HMAC_SECRET)

        user = db.query(User).filter(User.user_id == user_data.user_id).first()
        if not user or user.is_banned or user.balance < 0:
            raise HTTPException(status_code=400, detail="User error")

        config = load_config()
        amount = config["money"]["default"]
        user.balance += amount
        user.total_earned += amount
        user.last_active_at = datetime.now(timezone.utc)
        
        db.commit()
        return {"balance": user.balance}
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error in add: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/add-click/")
async def add_click(user_data: TokenData = Depends(verify_token), 
                    db: Session = Depends(get_db), 
                    signature: str = Header(...),
                    client_ip: str = Depends(get_client_ip),
                    timestamp: int = Header(...)):
    try:
        if abs(int(time.time()) - timestamp) > REQUEST_TIMEOUT:
            raise HTTPException(status_code=400, detail="error")
        verify_hmac(f"{user_data.user_id}:{timestamp}", signature, HMAC_SECRET)

        user = db.query(User).filter(User.user_id == user_data.user_id).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        if user.is_banned or user.balance < 0:
            raise HTTPException(status_code=400, detail="User is banned")
        config = load_config()
        amount = config["money"]["click"]
        user.balance += amount
        user.total_earned += amount
        user.last_active_at = datetime.now(timezone.utc)
        db.commit()
        return {"balance": user.balance}
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error in add-click: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/withdraw/")
async def withdraw(request: TransactionRequest,
                   user_data: TokenData = Depends(verify_token), 
                   db: Session = Depends(get_db),
                   signature: str = Header(...),
                   client_ip: str = Depends(get_client_ip),
                   timestamp: int = Header(...)):
    try:
        user = db.query(User).filter(User.user_id == user_data.user_id).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        if user.is_banned or user.balance < 0:
            raise HTTPException(status_code=400, detail="User is banned")
        if user.balance < request.amount:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        
        verify_hmac(f"{user_data.user_id}:{request.amount}:{timestamp}", signature, HMAC_SECRET_WITHDRAW)

        try:
            wallet_address = decrypt(request.address)
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid encrypted address")
        
        # Создаем запись о выводе в базе данных
        withdrawal = Withdrawal(
            user_id=user.user_id,
            amount=request.amount,
            status=WithdrawalStatus.PENDING,
            payment_method=request.pay_method,
            payment_details=wallet_address
        )
        db.add(withdrawal)
        
        # Обновляем баланс пользователя и статистику
        user.balance -= request.amount
        user.total_withdrawn += request.amount
        user.last_active_at = datetime.now(timezone.utc)
        
        db.commit()
        db.refresh(withdrawal)
        
        logger.info(
            f"Withdrawal created: ID={withdrawal.id}, User={user.user_id}, "
            f"Amount={request.amount}, Method={request.pay_method}, IP={client_ip}"
        )
        
        return {
            "balance": user.balance,
            "status": "pending",
            "withdrawal_id": withdrawal.id
        }

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error in withdraw: {str(e)}")
        #try:
        #    await send_telegram_message(
        #        f"Withdraw error: {user_data.user_id if user_data else 'unknown'} : "
        #        f"{request.price} : {request.pay_method} : {request.address} : {str(e)}"
        #    )
        #except Exception as telegram_error:
        #    logger.error(f"Failed to send telegram error notification: {str(telegram_error)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/balance/")
async def get_balance(user_data: TokenData = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_data.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="error")
    return {"balance": user.balance}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
