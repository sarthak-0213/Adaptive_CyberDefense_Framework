from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    violation_type = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    severity = Column(String, default="medium", nullable=False)  # critical, high, medium, low
    status = Column(String, default="active", nullable=False)  # active, investigating, resolved
    description = Column(String, nullable=True)
    evidence_path = Column(String, nullable=True)

