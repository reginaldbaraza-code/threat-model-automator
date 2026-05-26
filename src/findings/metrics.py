"""
Threat model service metrics.

Calculates operational metrics for the TM service dashboard:
- Mean time to triage, schedule, remediate
- Open findings by severity
- Assessment throughput
- SLA compliance rates

Usage:
    metrics = ServiceMetrics(repo)
    dashboard_data = metrics.get_dashboard_summary()
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import sessionmaker
from sqlalchemy import func

from src.findings.models import Finding, Assessment, FindingStatus, FindingSeverity


@dataclass
class DashboardSummary:
    """Summary data for the TM service dashboard."""

    total_assessments: int
    total_findings: int
    open_findings: int
    overdue_findings: int
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]
    avg_days_to_remediate: float
    assessments_this_month: int
    remediation_rate: float  # % of findings remediated

    def to_dict(self) -> dict:
        return {
            "total_assessments": self.total_assessments,
            "total_findings": self.total_findings,
            "open_findings": self.open_findings,
            "overdue_findings": self.overdue_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_status": self.findings_by_status,
            "avg_days_to_remediate": round(self.avg_days_to_remediate, 1),
            "assessments_this_month": self.assessments_this_month,
            "remediation_rate": round(self.remediation_rate, 1),
        }


class ServiceMetrics:
    """Calculates and provides TM service metrics."""

    def __init__(self, session_factory: sessionmaker):
        self._session_factory = session_factory

    def get_dashboard_summary(self) -> DashboardSummary:
        """Calculate all dashboard metrics."""
        with self._session_factory() as session:
            total_assessments = session.query(func.count(Assessment.id)).scalar() or 0
            total_findings = session.query(func.count(Finding.id)).scalar() or 0

            # Open findings
            closed = [
                FindingStatus.REMEDIATED.value,
                FindingStatus.VERIFIED.value,
                FindingStatus.ACCEPTED.value,
                FindingStatus.WONT_FIX.value,
            ]
            open_findings = session.query(func.count(Finding.id)).filter(
                Finding.status.notin_(closed)
            ).scalar() or 0

            # Overdue
            overdue = session.query(func.count(Finding.id)).filter(
                Finding.due_date < datetime.utcnow(),
                Finding.status.notin_(closed),
            ).scalar() or 0

            # By severity
            by_severity = {}
            for sev in FindingSeverity:
                count = session.query(func.count(Finding.id)).filter(
                    Finding.severity == sev.value
                ).scalar() or 0
                by_severity[sev.value] = count

            # By status
            by_status = {}
            for status in FindingStatus:
                count = session.query(func.count(Finding.id)).filter(
                    Finding.status == status.value
                ).scalar() or 0
                by_status[status.value] = count

            # Avg days to remediate
            remediated = session.query(Finding).filter(
                Finding.remediated_at.isnot(None)
            ).all()

            if remediated:
                total_days = sum(
                    (f.remediated_at - f.created_at).days for f in remediated
                )
                avg_days = total_days / len(remediated)
            else:
                avg_days = 0.0

            # This month's assessments
            now = datetime.utcnow()
            month_start = now.replace(day=1, hour=0, minute=0, second=0)
            this_month = session.query(func.count(Assessment.id)).filter(
                Assessment.assessment_date >= month_start
            ).scalar() or 0

            # Remediation rate
            remediation_rate = 0.0
            if total_findings > 0:
                fixed = by_status.get(FindingStatus.REMEDIATED.value, 0) + \
                        by_status.get(FindingStatus.VERIFIED.value, 0)
                remediation_rate = (fixed / total_findings) * 100

            return DashboardSummary(
                total_assessments=total_assessments,
                total_findings=total_findings,
                open_findings=open_findings,
                overdue_findings=overdue,
                findings_by_severity=by_severity,
                findings_by_status=by_status,
                avg_days_to_remediate=avg_days,
                assessments_this_month=this_month,
                remediation_rate=remediation_rate,
            )
