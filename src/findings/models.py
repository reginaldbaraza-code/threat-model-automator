"""
Findings database models.

Tracks threat model findings through their remediation lifecycle.
Uses SQLAlchemy for ORM with SQLite as default backend.

Models:
    Finding — An identified threat from a TM session
    Assessment — A completed threat model assessment
"""

from datetime import datetime, timedelta
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, Integer, String, DateTime, Float, ForeignKey, Text, Boolean,
    create_engine, Enum,
)
from sqlalchemy.orm import declarative_base, relationship, Session, sessionmaker


Base = declarative_base()


class FindingStatus(PyEnum):
    OPEN = "Open"
    ACKNOWLEDGED = "Acknowledged"
    IN_PROGRESS = "In Progress"
    REMEDIATED = "Remediated"
    VERIFIED = "Verified"
    ACCEPTED = "Risk Accepted"
    WONT_FIX = "Won't Fix"


class FindingSeverity(PyEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Assessment(Base):
    """A completed threat model assessment."""

    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    jira_key = Column(String(20), unique=True, nullable=False)
    service_name = Column(String(200), nullable=False)
    team = Column(String(200))
    assessor = Column(String(100))
    assessment_date = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="Completed")
    components_count = Column(Integer, default=0)
    dataflows_count = Column(Integer, default=0)
    duration_hours = Column(Float, default=1.5)
    notes = Column(Text, default="")

    # Relationship
    findings = relationship("Finding", back_populates="assessment")

    def findings_summary(self) -> dict:
        """Count findings by severity."""
        summary = {s.value: 0 for s in FindingSeverity}
        for f in self.findings:
            if f.severity in summary:
                summary[f.severity] += 1
        return summary


class Finding(Base):
    """An identified threat from a threat model assessment."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    threat_id = Column(String(20), nullable=False)  # e.g., "THR-001"
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    stride_category = Column(String(50))
    severity = Column(String(20), default=FindingSeverity.MEDIUM.value)
    dread_score = Column(Integer, default=0)
    status = Column(String(30), default=FindingStatus.OPEN.value)
    target_component = Column(String(200))
    mitigation = Column(Text, default="")
    owner = Column(String(100))
    due_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    remediated_at = Column(DateTime)
    verified_at = Column(DateTime)
    is_false_positive = Column(Boolean, default=False)

    # Relationship
    assessment = relationship("Assessment", back_populates="findings")

    @property
    def is_overdue(self) -> bool:
        """Check if the finding is past its due date."""
        if self.due_date and self.status not in (
            FindingStatus.REMEDIATED.value,
            FindingStatus.VERIFIED.value,
            FindingStatus.ACCEPTED.value,
            FindingStatus.WONT_FIX.value,
        ):
            return datetime.utcnow() > self.due_date
        return False

    @property
    def days_open(self) -> int:
        """Number of days since the finding was created."""
        return (datetime.utcnow() - self.created_at).days


def create_database(url: str = "sqlite:///findings.db") -> sessionmaker:
    """Create database tables and return a session factory."""
    engine = create_engine(url, echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)
