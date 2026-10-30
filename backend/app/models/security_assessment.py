from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class SecurityAssessment(Base):
    __tablename__ = "security_assessments"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String, nullable=False, default="completed")  # "in_progress", "completed", "failed"
    started_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    completed_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=True
    )
    summary_json = Column(Text, nullable=True)

    user = relationship("User")
    results = relationship("AssessmentResult", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("SecurityFinding", back_populates="assessment", cascade="all, delete-orphan")


class AssessmentResult(Base):
    __tablename__ = "assessment_results"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("security_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    section = Column(String, nullable=False, index=True)  # network, portal, http_https, session, access_control, segmentation, hardening
    status = Column(String, nullable=False, default="PASS")  # PASS, WARNING, FAIL, NOT_ASSESSED
    details_json = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    assessment = relationship("SecurityAssessment", back_populates="results")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("security_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    section = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="LOW")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, nullable=False, default="WARNING")  # PASS, WARNING, FAIL, NOT_ASSESSED
    finding = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    assessment = relationship("SecurityAssessment", back_populates="findings")
