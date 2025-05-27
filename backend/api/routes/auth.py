"""Authentication API routes."""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext

from backend.core.config import get_config
from backend.core.logging import get_logger

router = APIRouter()
logger = get_logger("api.auth")
config = get_config()

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Mock user database (in production, use a real database)
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"),
        "email": "admin@secureml.com",
        "is_active": True,
        "roles": ["admin"],
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": pwd_context.hash("analyst123"),
        "email": "analyst@secureml.com",
        "is_active": True,
        "roles": ["analyst"],
    },
}


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str
    expires_in: int
    user_info: Dict[str, Any]


class UserInfo(BaseModel):
    """User information model."""
    username: str
    email: str
    roles: list
    is_active: bool


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user."""
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=config.security.jwt_expires_minutes)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        config.security.jwt_secret,
        algorithm=config.security.jwt_algorithm
    )
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Verify JWT token and return user info."""
    try:
        payload = jwt.decode(
            credentials.credentials,
            config.security.jwt_secret,
            algorithms=[config.security.jwt_algorithm]
        )
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = USERS_DB.get(username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return user
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest) -> TokenResponse:
    """Authenticate user and return access token."""
    try:
        user = authenticate_user(request.username, request.password)
        if not user:
            logger.warning(f"Failed login attempt for username: {request.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        
        access_token_expires = timedelta(minutes=config.security.jwt_expires_minutes)
        access_token = create_access_token(
            data={"sub": user["username"]},
            expires_delta=access_token_expires
        )
        
        logger.info(f"Successful login for user: {request.username}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=config.security.jwt_expires_minutes * 60,
            user_info={
                "username": user["username"],
                "email": user["email"],
                "roles": user["roles"],
                "is_active": user["is_active"],
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


@router.get("/me", response_model=UserInfo)
async def get_current_user(current_user: Dict[str, Any] = Depends(verify_token)) -> UserInfo:
    """Get current user information."""
    return UserInfo(
        username=current_user["username"],
        email=current_user["email"],
        roles=current_user["roles"],
        is_active=current_user["is_active"],
    )


@router.post("/logout")
async def logout(current_user: Dict[str, Any] = Depends(verify_token)) -> Dict[str, str]:
    """Logout user (in a real implementation, you'd invalidate the token)."""
    logger.info(f"User logged out: {current_user['username']}")
    return {"message": "Successfully logged out"}


@router.post("/refresh")
async def refresh_token(current_user: Dict[str, Any] = Depends(verify_token)) -> TokenResponse:
    """Refresh access token."""
    try:
        access_token_expires = timedelta(minutes=config.security.jwt_expires_minutes)
        access_token = create_access_token(
            data={"sub": current_user["username"]},
            expires_delta=access_token_expires
        )
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=config.security.jwt_expires_minutes * 60,
            user_info={
                "username": current_user["username"],
                "email": current_user["email"],
                "roles": current_user["roles"],
                "is_active": current_user["is_active"],
            }
        )
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.get("/validate")
async def validate_token(current_user: Dict[str, Any] = Depends(verify_token)) -> Dict[str, Any]:
    """Validate current token."""
    return {
        "valid": True,
        "user": {
            "username": current_user["username"],
            "roles": current_user["roles"],
        }
    } 