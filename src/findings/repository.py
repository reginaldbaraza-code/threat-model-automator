"""
Findings repository — CRUD operations and queries.

Provides a clean interface over SQLAlchemy for managing
findings and assessments.

Usage:
    SessionFactory = create_database()
    repo = FindingsRepository(SessionFactory)
    repo.create_finding(assessment_id=1, title="Missing auth", ...)
    critical = repo.get_by_severity("Critical")
"""

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session, sessionmaker

from src.findings.models import (
    Finding, Assessment, FindingStatus, FindingSeverity,
    create_database,
)


class FindingsRepository:
    """
    Repository for threat model findings.

    Handles CRUD operations and common queries for the findings database.
    """

    def __init__(self, session_factory: sessionmaker):
        self._session_factory = session_factory

    @classmethod
    def from_url(cls, url: str = "sqlite:///findings.db") -> "FindingsRepository":
        """Create a repository with a new database connection."""
        factory = create_database(url)
        return cls(factory)

    def _session(self) -> Session:
        return self._session_factory()

    # === Assessment Operations ===

    def create_assessment(self, **kwargs) -> Assessment:
        """Create a new assessment record."""
        with self._session() as session:
            assessment = Assessment(**kwargs)
            session.add(assessment)
            session.commit()
            session.refresh(assessment)
            return assessment

    def get_assessment(self, assessment_id: int) -> Optional[Assessment]:
        """Get an assessment by ID."""
        with self._session() as session:
            return session.get(Assessment, assessment_id)

    def get_assessment_by_jira(self, jira_key: str) -> Optional[Assessment]:
        """Get an assessment by Jira key."""
        with self._session() as session:
            return session.query(Assessment).filter(
                Assessment.jira_key == jira_key
            ).first()

    # === Finding Operations ===

    def create_finding(self, **kwargs) -> Finding:
        """Create a new finding."""
        with self._session() as session:
            finding = Finding(**kwargs)
            session.add(finding)
            session.commit()
            session.refresh(finding)
            return finding

    def update_finding_status(
        self,
        finding_id: int,
        status: FindingStatus,
        owner: str = None,
    ) -> Optional[Finding]:
        """Update a finding's status."""
        with self._session() as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                return None

            finding.status = status.value
            finding.updated_at = datetime.utcnow()

            if owner:
                finding.owner = owner

            if status == FindingStatus.REMEDIATED:
                finding.remediated_at = datetime.utcnow()
            elif status == FindingStatus.VERIFIED:
                finding.verified_at = datetime.utcnow()

            session.commit()
            session.refresh(finding)
            return finding

    def get_finding(self, finding_id: int) -> Optional[Finding]:
        """Get a finding by ID."""
        with self._session() as session:
            return session.get(Finding, finding_id)

    # === Query Operations ===

    def get_open_findings(self) -> list[Finding]:
        """Get all findings that are not yet remediated or closed."""
        closed_statuses = [
            FindingStatus.REMEDIATED.value,
            FindingStatus.VERIFIED.value,
            FindingStatus.ACCEPTED.value,
            FindingStatus.WONT_FIX.value,
        ]
        with self._session() as session:
            return session.query(Finding).filter(
                Finding.status.notin_(closed_statuses)
            ).order_by(Finding.dread_score.desc()).all()

    def get_by_severity(self, severity: str) -> list[Finding]:
        """Get all findings of a specific severity."""
        with self._session() as session:
            return session.query(Finding).filter(
                Finding.severity == severity
            ).order_by(Finding.created_at.desc()).all()

    def get_overdue(self) -> list[Finding]:
        """Get all findings past their due date."""
        with self._session() as session:
            closed_statuses = [
                FindingStatus.REMEDIATED.value,
                FindingStatus.VERIFIED.value,
                FindingStatus.ACCEPTED.value,
                FindingStatus.WONT_FIX.value,
            ]
            return session.query(Finding).filter(
                Finding.due_date < datetime.utcnow(),
                Finding.status.notin_(closed_statuses),
            ).order_by(Finding.due_date.asc()).all()

    def get_by_owner(self, owner: str) -> list[Finding]:
        """Get all findings assigned to a specific owner."""
        with self._session() as session:
            return session.query(Finding).filter(
                Finding.owner == owner
            ).order_by(Finding.dread_score.desc()).all()
