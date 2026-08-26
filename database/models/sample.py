from typing import Optional, Any, Dict
from sqlalchemy import String, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database.session import Base

class RansomwareSample(Base):
    __tablename__ = "ransomware_samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    sha1: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    family_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ransomware_families.id"), nullable=True)
    variant: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    sample_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column("metadata", JSON, nullable=True)

    family = relationship("RansomwareFamily", back_populates="samples")
