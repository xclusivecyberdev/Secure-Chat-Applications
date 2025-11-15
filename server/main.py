"""
FastAPI server for end-to-end encrypted chat application.

This server:
- Handles user registration and authentication
- Manages prekey bundles for X3DH key exchange
- Relays encrypted messages via WebSocket (does NOT store messages)
- Provides REST API for user management
"""

import json
import asyncio
from typing import Dict, Set
from datetime import timedelta
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from contextlib import asynccontextmanager

from .database import Database, User
from .auth import create_access_token, verify_token, Token, ACCESS_TOKEN_EXPIRE_MINUTES


# Pydantic models for API
class UserRegister(BaseModel):
    username: str
    password: str
    identity_key: str


class UserLogin(BaseModel):
    username: str
    password: str


class PreKeyBundle(BaseModel):
    signed_pre_key: str
    one_time_pre_keys: list[str]


class Message(BaseModel):
    to_user: str
    encrypted_data: dict


# WebSocket connection manager
class ConnectionManager:
    """Manages active WebSocket connections"""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_tokens: Dict[str, str] = {}

    async def connect(self, username: str, websocket: WebSocket):
        """Accept and store a WebSocket connection"""
        await websocket.accept()
        self.active_connections[username] = websocket

    def disconnect(self, username: str):
        """Remove a WebSocket connection"""
        if username in self.active_connections:
            del self.active_connections[username]
        if username in self.user_tokens:
            del self.user_tokens[username]

    async def send_message(self, username: str, message: dict):
        """Send a message to a specific user"""
        if username in self.active_connections:
            await self.active_connections[username].send_json(message)

    def is_online(self, username: str) -> bool:
        """Check if a user is online"""
        return username in self.active_connections

    def get_online_users(self) -> list[str]:
        """Get list of online users"""
        return list(self.active_connections.keys())


# Initialize database and connection manager
db = Database()
manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    await db.create_tables()
    print("Database initialized")
    yield
    # Shutdown
    print("Server shutting down")


# Create FastAPI app
app = FastAPI(
    title="Encrypted Chat Server",
    description="End-to-end encrypted chat with Signal Protocol-inspired encryption",
    version="1.0.0",
    lifespan=lifespan
)


# Serve static files for web interface
try:
    app.mount("/static", StaticFiles(directory="web/static"), name="static")
except Exception:
    pass  # Static files may not exist yet


@app.get("/", response_class=HTMLResponse)
async def get_web_interface():
    """Serve the web interface"""
    try:
        with open("web/index.html") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Web interface not found. Use the CLI client instead.</h1>"


@app.post("/api/register", response_model=Token)
async def register(user_data: UserRegister):
    """
    Register a new user account.

    The client generates their identity keypair and sends the public key.
    """
    user = await db.create_user(
        username=user_data.username,
        password=user_data.password,
        identity_key=user_data.identity_key
    )

    if not user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Create access token
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        username=user.username
    )


@app.post("/api/login", response_model=Token)
async def login(user_data: UserLogin):
    """Authenticate a user and return JWT token"""
    user = await db.authenticate_user(user_data.username, user_data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Create access token
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        username=user.username
    )


@app.post("/api/prekeys/{username}")
async def upload_prekeys(username: str, bundle: PreKeyBundle, token: str = Depends(verify_token)):
    """
    Upload prekey bundle for X3DH key exchange.

    Requires authentication token.
    """
    if token != username:
        raise HTTPException(status_code=403, detail="Not authorized")

    await db.store_prekey_bundle(
        username=username,
        signed_pre_key=bundle.signed_pre_key,
        one_time_pre_keys=json.dumps(bundle.one_time_pre_keys)
    )

    return {"status": "success", "message": "Prekeys uploaded"}


@app.get("/api/prekeys/{username}")
async def get_prekeys(username: str):
    """
    Get prekey bundle for a user (for initiating encrypted session).

    This is public - anyone can request prekeys to start a conversation.
    """
    bundle = await db.get_prekey_bundle(username)

    if not bundle:
        raise HTTPException(status_code=404, detail="User not found or no prekeys available")

    return bundle


@app.get("/api/users")
async def list_users():
    """List all registered users"""
    users = await db.list_users()
    return {"users": users}


@app.get("/api/users/online")
async def list_online_users():
    """List currently online users"""
    return {"users": manager.get_online_users()}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time messaging.

    Protocol:
    1. Client sends: {"type": "auth", "token": "jwt_token"}
    2. Server verifies and responds: {"type": "auth_success", "username": "..."}
    3. Client sends messages: {"type": "message", "to": "recipient", "data": {...}}
    4. Server relays to recipient: {"type": "message", "from": "sender", "data": {...}}
    """
    username = None

    try:
        await websocket.accept()

        # Wait for authentication
        auth_data = await websocket.receive_json()

        if auth_data.get("type") != "auth":
            await websocket.send_json({"type": "error", "message": "Authentication required"})
            await websocket.close()
            return

        token = auth_data.get("token")
        username = verify_token(token)

        if not username:
            await websocket.send_json({"type": "error", "message": "Invalid token"})
            await websocket.close()
            return

        # Store connection
        manager.active_connections[username] = websocket
        await websocket.send_json({
            "type": "auth_success",
            "username": username,
            "online_users": manager.get_online_users()
        })

        # Notify others that user is online
        for other_user in manager.active_connections:
            if other_user != username:
                await manager.send_message(other_user, {
                    "type": "user_online",
                    "username": username
                })

        # Message handling loop
        while True:
            data = await websocket.receive_json()

            if data.get("type") == "message":
                recipient = data.get("to")
                message_data = data.get("data")

                if not recipient or not message_data:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Invalid message format"
                    })
                    continue

                # Relay message to recipient
                if manager.is_online(recipient):
                    await manager.send_message(recipient, {
                        "type": "message",
                        "from": username,
                        "data": message_data
                    })
                    # Confirm delivery
                    await websocket.send_json({
                        "type": "delivered",
                        "to": recipient
                    })
                else:
                    # Recipient offline
                    await websocket.send_json({
                        "type": "error",
                        "message": f"User {recipient} is offline"
                    })

            elif data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if username:
            manager.disconnect(username)
            # Notify others that user is offline
            for other_user in manager.active_connections:
                await manager.send_message(other_user, {
                    "type": "user_offline",
                    "username": username
                })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
