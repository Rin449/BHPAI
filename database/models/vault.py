"""
BHPAI Database Models for Encrypted Backup Vault
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy import String, DateTime, Integer, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.session import Base


class VaultUser(Base):
    __tablename__ = "vault_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    salt_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    pake_verifier: Mapped[str] = mapped_column(String(1024), nullable=False)
    encrypted_k_vault: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone=utc)
    )

    blobs: Mapped[list["VaultBlob"]] = relationship("VaultBlob", back_populates="user", cascade="all, delete-orphan")


class VaultBlob(Base):
    __tablename__ = "vault_blobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vault_id: Mapped[str] = mapped_column(String(36), ForeignKey("vault_users.id"), nullable=False, index=True)
    backup_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    object_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    encrypted_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    encrypted_dek_envelope: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    file_envelope: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped["VaultUser"] = relationship("VaultUser", back_populates="blobs")
