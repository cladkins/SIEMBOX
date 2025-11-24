"""
SIEM BOX - Authentication Service
"""
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func
from fastapi import HTTPException, status
from app.core.config import settings
from app.models.users import User
from app.schemas.auth import UserCreate, TokenData


# Password hashing context (bcrypt_sha256 avoids the 72-byte bcrypt limit)
pwd_context = CryptContext(
    schemes=["bcrypt_sha256", "bcrypt"],
    deprecated="auto",
    default="bcrypt_sha256"
)

# JWT settings
ALGORITHM = "HS256"


class AuthService:
    """Service for handling authentication operations"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> TokenData:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            user_id: int = payload.get("user_id")
            
            if username is None or user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return TokenData(username=username, user_id=user_id)
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    @staticmethod
    async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
        """Get user by username"""
        query = select(User).where(User.username == username)
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email"""
        query = select(User).where(User.email == email)
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: int) -> Optional[User]:
        """Get user by ID"""
        query = select(User).where(User.id == user_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def authenticate_user(db: AsyncSession, username: str, password: str) -> Optional[User]:
        """Authenticate a user with username and password"""
        user = await AuthService.get_user_by_username(db, username)
        if not user:
            return None
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        return user
    
    @staticmethod
    async def create_user(db: AsyncSession, user_create: UserCreate) -> User:
        """Create a new user"""
        # Check if username already exists
        if await AuthService.get_user_by_username(db, user_create.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Check if email already exists
        if await AuthService.get_user_by_email(db, user_create.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create new user
        hashed_password = AuthService.get_password_hash(user_create.password)
        db_user = User(
            username=user_create.username,
            email=user_create.email,
            hashed_password=hashed_password,
            is_active=user_create.is_active,
            is_superuser=user_create.is_superuser
        )
        
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    
    @staticmethod
    async def update_last_login(db: AsyncSession, user_id: int) -> None:
        """Update user's last login timestamp"""
        query = update(User).where(User.id == user_id).values(last_login=func.now())
        await db.execute(query)
        await db.commit()
    
    @staticmethod
    async def create_default_admin(db: AsyncSession) -> User:
        """Create default admin user if it doesn't exist"""
        admin_user = await AuthService.get_user_by_username(db, "admin")
        if not admin_user:
            admin_create = UserCreate(
                username="admin",
                email="admin@example.com",
                password="admin123",
                is_active=True,
                is_superuser=True
            )
            admin_user = await AuthService.create_user(db, admin_create)
            print("Created default admin user: admin/admin123")
        return admin_user
    
    @staticmethod
    async def logout_user(db: AsyncSession, user_id: int) -> dict:
        """Logout user (for future token blacklisting if needed)"""
        # For now, just return success message
        # In production, you might want to blacklist the token
        return {"message": "Successfully logged out"}
    
    @staticmethod
    def refresh_token(token: str) -> dict:
        """Refresh an access token"""
        try:
            # Verify the current token
            token_data = AuthService.verify_token(token)
            
            # Create a new token with the same data
            access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
            new_access_token = AuthService.create_access_token(
                data={"sub": token_data.username, "user_id": token_data.user_id},
                expires_delta=access_token_expires
            )
            
            return {
                "access_token": new_access_token,
                "token_type": "bearer",
                "expires_in": settings.access_token_expire_minutes * 60
            }
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
