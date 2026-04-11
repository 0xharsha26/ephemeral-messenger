from __future__ import annotations

import os
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from pwdlib import PasswordHash
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select

# ============================================================
# Config
# ============================================================

SECRET_KEY = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET_123456789"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ephemeral_messenger.db")
DEFAULT_BURN_SECONDS = 10

INVITE_CODES = {
    "night-agent-alpha",
    }

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)

password_hasher = PasswordHash.recommended()
security = HTTPBearer(auto_error=False)


# ============================================================
# Database models
# ============================================================

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    invite_code_used: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    sender_id: int = Field(index=True)
    recipient_id: int = Field(index=True)
    ciphertext: str
    iv: str
    salt: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    read_at: Optional[datetime] = None
    burn_after_seconds: int = DEFAULT_BURN_SECONDS
    burn_at: Optional[datetime] = Field(default=None, index=True)
    status: str = Field(default="unread", index=True)


# ============================================================
# Schemas
# ============================================================

class RegisterRequest(BaseModel):
    username: str
    password: str
    invite_code: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    username: str
    created_at: datetime


class MessageCreate(BaseModel):
    recipient_username: str
    ciphertext: str
    iv: str
    salt: str
    burn_after_seconds: int = DEFAULT_BURN_SECONDS


class MessageOut(BaseModel):
    id: int
    sender_id: int
    sender_username: str
    recipient_id: int
    recipient_username: str
    ciphertext: str
    iv: str
    salt: str
    created_at: datetime
    read_at: Optional[datetime]
    burn_after_seconds: int
    burn_at: Optional[datetime]
    status: str


class ReadMessageResponse(BaseModel):
    message: MessageOut
    countdown_started: bool


# ============================================================
# Helpers
# ============================================================

def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(plain_password: str, stored_hash: str) -> bool:
    return password_hasher.verify(plain_password, stored_hash)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_username(session: Session, username: str) -> Optional[User]:
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()


def get_message_for_user(session: Session, message_id: int, user_id: int) -> Optional[Message]:
    statement = select(Message).where(
        Message.id == message_id,
        Message.recipient_id == user_id,
    )
    return session.exec(statement).first()


def serialize_message(session: Session, message: Message) -> MessageOut:
    sender = session.get(User, message.sender_id)
    recipient = session.get(User, message.recipient_id)

    return MessageOut(
        id=message.id,
        sender_id=message.sender_id,
        sender_username=sender.username if sender else "unknown",
        recipient_id=message.recipient_id,
        recipient_username=recipient.username if recipient else "unknown",
        ciphertext=message.ciphertext,
        iv=message.iv,
        salt=message.salt,
        created_at=message.created_at,
        read_at=message.read_at,
        burn_after_seconds=message.burn_after_seconds,
        burn_at=message.burn_at,
        status=message.status,
    )


def delete_expired_messages(session: Session) -> int:
    now = datetime.now(timezone.utc)
    statement = select(Message).where(
        Message.burn_at.is_not(None),
        Message.burn_at <= now,
    )
    expired = list(session.exec(statement).all())

    for item in expired:
        session.delete(item)

    session.commit()
    return len(expired)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    session: Session = Depends(get_session),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = get_user_by_username(session, username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# ============================================================
# WebSocket manager
# ============================================================

class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict[int, list[WebSocket]] = {}

    async def connect(self, user_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.setdefault(user_id, []).append(websocket)

    def disconnect(self, user_id: int, websocket: WebSocket) -> None:
        if user_id not in self.active_connections:
            return
        self.active_connections[user_id] = [
            ws for ws in self.active_connections[user_id] if ws is not websocket
        ]
        if not self.active_connections[user_id]:
            del self.active_connections[user_id]

    async def send_personal_message(self, user_id: int, data: dict) -> None:
        for ws in self.active_connections.get(user_id, []):
            await ws.send_json(data)


manager = ConnectionManager()


# ============================================================
# App
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(title="Ephemeral Messenger MVP", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict:
    return {"message": "Ephemeral Messenger API is running"}


@app.post("/auth/register", response_model=UserOut)
def register(payload: RegisterRequest, session: Session = Depends(get_session)) -> User:
    if payload.invite_code not in INVITE_CODES:
        raise HTTPException(status_code=400, detail="Invalid invite code")

    existing = get_user_by_username(session, payload.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        invite_code_used=payload.invite_code,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, session: Session = Depends(get_session)) -> TokenResponse:
    user = get_user_by_username(session, payload.username)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenResponse(access_token=access_token)


@app.get("/users/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@app.get("/users/me/id")
def get_my_id(current_user: User = Depends(get_current_user)) -> dict:
    return {
        "id": current_user.id,
        "username": current_user.username,
    }


@app.post("/messages", response_model=MessageOut)
async def send_message(
    payload: MessageCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> MessageOut:
    if payload.burn_after_seconds < 1 or payload.burn_after_seconds > 300:
        raise HTTPException(status_code=400, detail="Burn time must be between 1 and 300 seconds")

    recipient = get_user_by_username(session, payload.recipient_username)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    if not payload.ciphertext or not payload.iv or not payload.salt:
        raise HTTPException(status_code=400, detail="Encrypted payload is incomplete")

    message = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        ciphertext=payload.ciphertext,
        iv=payload.iv,
        salt=payload.salt,
        burn_after_seconds=payload.burn_after_seconds,
    )
    session.add(message)
    session.commit()
    session.refresh(message)

    await manager.send_personal_message(
        recipient.id,
        {
            "type": "new_message",
            "message_id": message.id,
            "sender_username": current_user.username,
            "recipient_username": recipient.username,
            "created_at": message.created_at.isoformat(),
        },
    )

    return serialize_message(session, message)


@app.get("/messages/inbox", response_model=list[MessageOut])
def get_inbox(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[MessageOut]:
    delete_expired_messages(session)
    statement = select(Message).where(Message.recipient_id == current_user.id)
    messages = list(session.exec(statement).all())
    return [serialize_message(session, msg) for msg in messages]


@app.post("/messages/{message_id}/read", response_model=ReadMessageResponse)
async def read_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> ReadMessageResponse:
    delete_expired_messages(session)
    message = get_message_for_user(session, message_id, current_user.id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    countdown_started = False
    if message.status == "unread":
        now = datetime.now(timezone.utc)
        message.read_at = now
        message.burn_at = now + timedelta(seconds=message.burn_after_seconds)
        message.status = "burning"
        session.add(message)
        session.commit()
        session.refresh(message)
        countdown_started = True

        await manager.send_personal_message(
            current_user.id,
            {
                "type": "message_read",
                "message_id": message.id,
                "burn_at": message.burn_at.isoformat() if message.burn_at else None,
            },
        )

    return ReadMessageResponse(
        message=serialize_message(session, message),
        countdown_started=countdown_started,
    )


@app.delete("/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    statement = select(Message).where(
        Message.id == message_id,
        (Message.recipient_id == current_user.id) | (Message.sender_id == current_user.id),
    )
    message = session.exec(statement).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    session.delete(message)
    session.commit()
    return {"ok": True, "detail": "Message deleted"}


@app.post("/maintenance/cleanup")
def cleanup(session: Session = Depends(get_session)) -> dict:
    deleted = delete_expired_messages(session)
    return {"ok": True, "deleted": deleted}


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    await manager.connect(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)

app.mount("/app", StaticFiles(directory="frontend", html=True), name="frontend")

@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/app/login.html")

# Run with:
# python -m uvicorn ephemeral_messenger_backend:app --reload