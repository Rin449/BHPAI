from typing import Optional, List
from sqlalchemy import String, Text, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database.session import Base
import datetime

class RansomwareFamily(Base):
    __tablename__ = "ransomware_families"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    samples = relationship("RansomwareSample", back_populates="family")
    decryptors = relationship("Decryptor", back_populates="family")
