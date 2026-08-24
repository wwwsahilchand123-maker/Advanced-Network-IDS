"""
Pydantic schemas for authentication tokens
"""
from typing import Optional
from pydantic import BaseModel


class Token(BaseModel):
    """Token response schema"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Token payload schema"""
    sub: Optional[int] = None
    exp: Optional[int] = None
    type: Optional[str] = None


class RefreshToken(BaseModel):
    """Refresh token request schema"""
    refresh_token: str
