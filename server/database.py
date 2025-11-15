"""
Database models and operations for the chat server.

Uses SQLAlchemy with SQLite for storing user accounts and prekey bundles.
Note: Messages are NOT stored on the server - only relayed.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, Session
from passlib.context import CryptContext

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    """User account model"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    identity_key = Column(String(128), nullable=False)  # Ed25519 public key (hex)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    def verify_password(self, password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(password, self.hashed_password)

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)


class PreKey(Base):
    """Prekey bundle storage for X3DH key exchange"""
    __tablename__ = "prekeys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    username = Column(String(50), index=True, nullable=False)
    signed_pre_key = Column(String(128), nullable=False)  # X25519 public key (hex)
    one_time_pre_keys = Column(Text, nullable=True)  # JSON array of one-time keys
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Database:
    """Database manager for async operations"""

    def __init__(self, database_url: str = "sqlite+aiosqlite:///./chat.db"):
        """
        Initialize database connection.

        Args:
            database_url: SQLAlchemy database URL
        """
        self.engine = create_async_engine(database_url, echo=False)
        self.async_session = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def create_tables(self):
        """Create all tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def create_user(self, username: str, password: str, identity_key: str) -> Optional[User]:
        """
        Create a new user account.

        Args:
            username: Unique username
            password: Plain text password (will be hashed)
            identity_key: User's public identity key (hex)

        Returns:
            Created User object or None if username exists
        """
        async with self.async_session() as session:
            # Check if user exists
            from sqlalchemy import select
            result = await session.execute(select(User).where(User.username == username))
            if result.scalar_one_or_none():
                return None

            # Create user
            user = User(
                username=username,
                hashed_password=User.hash_password(password),
                identity_key=identity_key
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user

    async def get_user(self, username: str) -> Optional[User]:
        """
        Get user by username.

        Args:
            username: Username to look up

        Returns:
            User object or None if not found
        """
        async with self.async_session() as session:
            from sqlalchemy import select
            result = await session.execute(select(User).where(User.username == username))
            return result.scalar_one_or_none()

    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate a user.

        Args:
            username: Username
            password: Password to verify

        Returns:
            User object if authenticated, None otherwise
        """
        user = await self.get_user(username)
        if not user or not user.verify_password(password):
            return None
        return user

    async def store_prekey_bundle(self, username: str, signed_pre_key: str, one_time_keys: str):
        """
        Store or update prekey bundle for a user.

        Args:
            username: Username
            signed_pre_key: Signed prekey (hex)
            one_time_keys: JSON string of one-time prekeys
        """
        async with self.async_session() as session:
            from sqlalchemy import select
            # Get user
            result = await session.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                return

            # Check if prekey bundle exists
            result = await session.execute(select(PreKey).where(PreKey.username == username))
            prekey = result.scalar_one_or_none()

            if prekey:
                # Update existing
                prekey.signed_pre_key = signed_pre_key
                prekey.one_time_pre_keys = one_time_keys
                prekey.updated_at = datetime.utcnow()
            else:
                # Create new
                prekey = PreKey(
                    user_id=user.id,
                    username=username,
                    signed_pre_key=signed_pre_key,
                    one_time_pre_keys=one_time_keys
                )
                session.add(prekey)

            await session.commit()

    async def get_prekey_bundle(self, username: str) -> Optional[dict]:
        """
        Get prekey bundle for a user.

        Args:
            username: Username to get keys for

        Returns:
            Dictionary with identity_key, signed_pre_key, and one_time_pre_key
        """
        async with self.async_session() as session:
            from sqlalchemy import select
            # Get user
            result = await session.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                return None

            # Get prekeys
            result = await session.execute(select(PreKey).where(PreKey.username == username))
            prekey = result.scalar_one_or_none()
            if not prekey:
                return None

            # Parse one-time keys
            import json
            one_time_keys = json.loads(prekey.one_time_pre_keys) if prekey.one_time_pre_keys else []

            # Get and remove one one-time key
            one_time_key = None
            if one_time_keys:
                one_time_key = one_time_keys.pop(0)
                prekey.one_time_pre_keys = json.dumps(one_time_keys)
                await session.commit()

            return {
                'identity_key': user.identity_key,
                'signed_pre_key': prekey.signed_pre_key,
                'one_time_pre_key': one_time_key
            }

    async def list_users(self) -> List[str]:
        """
        List all registered usernames.

        Returns:
            List of usernames
        """
        async with self.async_session() as session:
            from sqlalchemy import select
            result = await session.execute(select(User.username).where(User.is_active == True))
            return [row[0] for row in result.all()]
