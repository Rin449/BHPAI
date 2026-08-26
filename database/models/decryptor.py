from typing import Optional, Any, Dict
from sqlalchemy import String, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database.session import Base

class Decryptor(Base):
    __tablename__ = "decryptors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    family_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ransomware_families.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0")
    author: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    config: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    family = relationship("RansomwareFamily", back_populates="decryptors")
