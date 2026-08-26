from typing import Optional
from sqlalchemy import String, Float, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database.session import Base

class Fingerprint(Base):
    __tablename__ = "fingerprints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sample_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ransomware_samples.id"), nullable=True)
    pattern_type: Mapped[str] = mapped_column(String(100), nullable=False)
    pattern_value: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    sample = relationship("RansomwareSample")
