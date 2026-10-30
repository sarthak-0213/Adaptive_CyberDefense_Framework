import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
import jwt
from sqlalchemy.orm import Session

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.models.user import User, TokenBlacklist
from app.schemas.auth import UserRegister, TokenResponse

logger = logging.getLogger("security")


class AuthService:
    @staticmethod
    def register_user(db: Session, user_data: UserRegister) -> User:
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            logger.warning(f"Registration attempt failed: Email {user_data.email} already exists.")
            raise ValueError("Email already registered")

        hashed = hash_password(user_data.password)
        new_user = User(
            email=user_data.email,
            hashed_password=hashed,
            role=user_data.role or "user"
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info(f"User registered successfully: ID {new_user.id}, Email {new_user.email}, Role {new_user.role}")
        return new_user

    @staticmethod
    def authenticate_user(db: Session, email: str, plain_password: str) -> User:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            logger.warning(f"Authentication failed: User with email {email} not found.")
            raise ValueError("Incorrect email or password")

        if not user.is_active:
            logger.warning(f"Authentication failed: User {email} is inactive.")
            raise ValueError("User account is inactive")

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            logger.warning(f"Authentication failed: User {email} is locked out until {user.locked_until}.")
            raise ValueError("Account is temporarily locked due to too many failed attempts")

        if not verify_password(plain_password, user.hashed_password):
            user.failed_logins += 1
            if user.failed_logins >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                logger.warning(f"User {email} locked out due to multiple failed attempts.")
            db.commit()
            logger.warning(f"Authentication failed: Incorrect password for {email}.")
            raise ValueError("Incorrect email or password")

        if user.failed_logins > 0 or user.locked_until:
            user.failed_logins = 0
            user.locked_until = None
            db.commit()

        logger.info(f"User authenticated successfully: ID {user.id}, Email {user.email}")
        return user

    @staticmethod
    def create_tokens_for_user(db: Any, user: User = None, ip_address: str = None, device_info: str = None) -> TokenResponse:
        from sqlalchemy.orm import object_session
        from app.models.user import ActiveSession, User as UserModel
        if isinstance(db, UserModel):
            user = db
            db = object_session(user)

        access_token = create_access_token(user_id=user.id, role=user.role)
        refresh_token = create_refresh_token(user_id=user.id, role=user.role)
        
        try:
            payload = jwt.decode(refresh_token, options={"verify_signature": False})
            exp_timestamp = payload.get("exp")
            expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc) if exp_timestamp else datetime.now(timezone.utc) + timedelta(days=7)
        except Exception:
            expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        if db is not None:
            session_entry = ActiveSession(
                user_id=user.id,
                refresh_token=refresh_token,
                ip_address=ip_address,
                device_info=device_info,
                expires_at=expires_at
            )
            db.add(session_entry)
            db.commit()
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    @staticmethod
    def blacklist_token(db: Session, token: str, token_type: str) -> None:
        try:
            # We try to decode the token to find its expiration date
            # Ignore expiration exception when blacklisting expired tokens
            secret_key = None
            # We can decode without verification just to inspect, or verify with lax options
            payload = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = payload.get("exp")
            expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc) if exp_timestamp else datetime.now(timezone.utc)
        except Exception:
            expires_at = datetime.now(timezone.utc)

        # Check if already blacklisted
        existing = db.query(TokenBlacklist).filter(TokenBlacklist.token == token).first()
        if not existing:
            blacklist_entry = TokenBlacklist(
                token=token,
                token_type=token_type,
                expires_at=expires_at
            )
            db.add(blacklist_entry)
            db.commit()
            logger.info(f"Token blacklisted successfully: Type {token_type}")

    @staticmethod
    def is_token_blacklisted(db: Session, token: str) -> bool:
        # Check database
        blacklisted = db.query(TokenBlacklist).filter(TokenBlacklist.token == token).first()
        if blacklisted:
            return True
        return False

    @staticmethod
    def refresh_access_token(db: Session, refresh_token: str, ip_address: str = None, device_info: str = None) -> TokenResponse:
        from app.models.user import ActiveSession
        # Check reuse
        is_blacklisted = AuthService.is_token_blacklisted(db, refresh_token)
        session_entry = db.query(ActiveSession).filter(ActiveSession.refresh_token == refresh_token).first()
        
        if is_blacklisted or (session_entry and session_entry.is_revoked):
            # Token Reuse Detected! Revoke all sessions for user.
            logger.critical(f"Token reuse detected for refresh token! Revoking all sessions.")
            if session_entry:
                db.query(ActiveSession).filter(ActiveSession.user_id == session_entry.user_id).update({"is_revoked": True})
                db.commit()
            raise ValueError("Refresh token has been revoked. All sessions terminated.")
            
        if not session_entry:
            raise ValueError("Invalid session")

        try:
            payload = decode_token(refresh_token, is_refresh=True)
            if payload.get("type") != "refresh":
                raise ValueError("Invalid token type")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token refresh failed: {str(e)}")
            raise ValueError(str(e))

        user_id = payload.get("user_id")
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise ValueError("User not found or inactive")

        # Revoke old token and session
        AuthService.blacklist_token(db, refresh_token, "refresh")
        session_entry.is_revoked = True
        db.commit()

        # Generate new tokens
        return AuthService.create_tokens_for_user(db, user, ip_address, device_info)

    @staticmethod
    def logout(db: Session, access_token: str, refresh_token: str) -> None:
        from app.models.user import ActiveSession
        # Blacklist both tokens
        AuthService.blacklist_token(db, access_token, "access")
        AuthService.blacklist_token(db, refresh_token, "refresh")
        
        session_entry = db.query(ActiveSession).filter(ActiveSession.refresh_token == refresh_token).first()
        if session_entry:
            session_entry.is_revoked = True
            db.commit()
            
        logger.info("User logged out successfully and tokens revoked.")

    @staticmethod
    def request_password_reset(db: Session, email: str) -> None:
        import secrets
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return

        token = secrets.token_urlsafe(32)
        user.reset_token = token
        user.reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        db.commit()
        
        logger.info(f"Password reset requested for {email}. Token: {token}")

    @staticmethod
    def confirm_password_reset(db: Session, token: str, new_password: str) -> None:
        user = db.query(User).filter(User.reset_token == token).first()
        if not user:
            raise ValueError("Invalid or expired reset token")
            
        if user.reset_token_expires and user.reset_token_expires < datetime.now(timezone.utc):
            raise ValueError("Reset token has expired")
            
        user.hashed_password = hash_password(new_password)
        user.reset_token = None
        user.reset_token_expires = None
        user.failed_logins = 0
        user.locked_until = None
        
        from app.models.user import ActiveSession
        db.query(ActiveSession).filter(ActiveSession.user_id == user.id).update({"is_revoked": True})
        db.commit()
        logger.info(f"Password reset successful for {user.email}. All previous sessions revoked.")
