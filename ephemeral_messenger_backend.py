from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ephemeral_messenger.db")
DEFAULT_BURN_SECONDS = 10

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
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


class GuestEnterRequest(BaseModel):
    username: str


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


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


def normalize_username(username: str) -> str:
    cleaned = username.strip().lower()

    if not cleaned:
        raise HTTPException(status_code=400, detail="Username is required")

    if len(cleaned) > 30:
        raise HTTPException(status_code=400, detail="Username must be 30 characters or less")

    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_-")
    if any(ch not in allowed for ch in cleaned):
        raise HTTPException(
            status_code=400,
            detail="Username can only contain letters, numbers, underscore, and hyphen",
        )

    return cleaned


def get_user_by_username(session: Session, username: str) -> Optional[User]:
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()


def get_or_create_user(session: Session, username: str) -> User:
    username = normalize_username(username)

    user = get_user_by_username(session, username)
    if user:
        return user

    user = User(username=username)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def get_current_guest_user(
    x_username: str = Header(...),
    session: Session = Depends(get_session),
) -> User:
    return get_or_create_user(session, x_username)


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

async def cleanup_loop() -> None:
    while True:
        try:
            with Session(engine) as session:
                deleted = delete_expired_messages(session)
                if deleted:
                    print(f"Auto-cleanup deleted {deleted} expired message(s)")
        except Exception as exc:
            print(f"Auto-cleanup error: {exc}")

        await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()

    cleanup_task = asyncio.create_task(cleanup_loop())

    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Ephemeral Messenger MVP", lifespan=lifespan)

app.mount("/app", StaticFiles(directory="frontend", html=True), name="frontend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/app/login.html")


@app.post("/guest/enter", response_model=UserOut)
def guest_enter(payload: GuestEnterRequest, session: Session = Depends(get_session)) -> User:
    return get_or_create_user(session, payload.username)


@app.get("/users/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_guest_user)) -> User:
    return current_user


@app.get("/users/me/id")
def get_my_id(current_user: User = Depends(get_current_guest_user)) -> dict:
    return {
        "id": current_user.id,
        "username": current_user.username,
    }


@app.post("/messages", response_model=MessageOut)
async def send_message(
    payload: MessageCreate,
    current_user: User = Depends(get_current_guest_user),
    session: Session = Depends(get_session),
) -> MessageOut:
    if payload.burn_after_seconds < 1 or payload.burn_after_seconds > 300:
        raise HTTPException(status_code=400, detail="Burn time must be between 1 and 300 seconds")

    recipient_username = normalize_username(payload.recipient_username)
    recipient = get_user_by_username(session, recipient_username)

    if not recipient:
        recipient = get_or_create_user(session, recipient_username)

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
    current_user: User = Depends(get_current_guest_user),
    session: Session = Depends(get_session),
) -> list[MessageOut]:
    delete_expired_messages(session)
    statement = select(Message).where(Message.recipient_id == current_user.id)
    messages = list(session.exec(statement).all())
    return [serialize_message(session, msg) for msg in messages]


@app.post("/messages/{message_id}/read", response_model=ReadMessageResponse)
async def read_message(
    message_id: int,
    current_user: User = Depends(get_current_guest_user),
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
    current_user: User = Depends(get_current_guest_user),
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

# Run locally:
# python -m uvicorn ephemeral_messenger_backend:app --reload