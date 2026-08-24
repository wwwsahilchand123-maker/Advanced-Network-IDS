"""
Pydantic schemas for User
"""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, validator

from app.core.security import validate_password_strength


class UserBase(BaseModel):
    """Base user schema"""
    username: str
    email: EmailStr
    role: str = "viewer"


class UserCreate(UserBase):
    """Schema for creating a user"""
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        validate_password_strength(v)
        return v
    
    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ['admin', 'analyst', 'viewer']
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of: {', '.join(allowed_roles)}")
        return v


class UserUpdate(BaseModel):
    """Schema for updating a user"""
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if v:
            validate_password_strength(v)
        return v


class UserInDBBase(UserBase):
    """Base schema for user in database"""
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True


class User(UserInDBBase):
    """Schema for user response"""
    pass


class UserInDB(UserInDBBase):
    """Schema for user in database with password hash"""
    password_hash: str
