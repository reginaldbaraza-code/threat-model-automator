"""
SLA monitoring for threat model requests.

Tracks response and resolution times against configurable targets.
Flags breached or at-risk SLAs for alerting.

Default SLA targets:
    - Response (New → Triaged): 24 hours
    - Schedule (Triaged → Scheduled): 5 business days
    - Resolution (New → Closed): 14 business days
    - Critical findings remediation: 7 days
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from src.jira.client import TMRequest, TMStatus, TMPriority


class SLAStatus(Enum):
    """SLA compliance status."""

    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    BREACHED = "breached"


@dataclass
class SLATarget:
    """Defines an SLA target with thresholds."""

    name: str
    target_hours: float
    warning_threshold: float = 0.8  # Alert at 80% of target

    @property
    def warning_hours(self) -> float:
        return self.target_hours * self.warning_threshold


@dataclass
class SLACheck:
    """Result of checking a request against its SLA."""

    request_key: str
    sla_name: str
    status: SLAStatus
    elapsed_hours: float
    target_hours: float
    remaining_hours: float
    message: str


# Default SLA targets by priority
DEFAULT_SLAS: dict[TMPriority, dict[str, SLATarget]] = {
    TMPriority.CRITICAL: {
        "response": SLATarget("Response", target_hours=4),
        "schedule": SLATarget("Schedule", target_hours=24),
        "resolution": SLATarget("Resolution", target_hours=120),  # 5 days
    },
    TMPriority.HIGH: {
        "response": SLATarget("Response", target_hours=24),
        "schedule": SLATarget("Schedule", target_hours=72),
        "resolution": SLATarget("Resolution", target_hours=240),  # 10 days
    },
    TMPriority.MEDIUM: {
        "response": SLATarget("Response", target_hours=48),
        "schedule": SLATarget("Schedule", target_hours=120),
        "resolution": SLATarget("Resolution", target_hours=336),  # 14 days
    },
    TMPriority.LOW: {
        "response": SLATarget("Response", target_hours=120),
        "schedule": SLATarget("Schedule", target_hours=240),
        "resolution": SLATarget("Resolution", target_hours=720),  # 30 days
    },
}


class SLAMonitor:
    """
    Monitors SLA compliance for TM requests.

    Usage:
        monitor = SLAMonitor()
        checks = monitor.check_all(open_requests)
        breached = [c for c in checks if c.status == SLAStatus.BREACHED]
    """

    def __init__(self, sla_config: dict = None):
        self.slas = sla_config or DEFAULT_SLAS

    def check_request(self, request: TMRequest) -> list[SLACheck]:
        """Check all applicable SLAs for a single request."""
        checks = []
        now = datetime.utcnow()

        try:
            created = datetime.fromisoformat(request.created.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            return checks

        targets = self.slas.get(request.priority, self.slas[TMPriority.MEDIUM])
        elapsed = (now - created).total_seconds() / 3600  # hours

        # Response SLA (New → Triaged)
        if request.status == TMStatus.NEW:
            checks.append(self._evaluate(
                request.key, "response", elapsed, targets["response"],
            ))

        # Schedule SLA (Triaged but not yet scheduled)
        if request.status == TMStatus.TRIAGED:
            checks.append(self._evaluate(
                request.key, "schedule", elapsed, targets["schedule"],
            ))

        # Resolution SLA (anything not closed)
        if request.status not in (TMStatus.CLOSED, TMStatus.CANCELLED):
            checks.append(self._evaluate(
                request.key, "resolution", elapsed, targets["resolution"],
            ))

        return checks

    def check_all(self, requests: list[TMRequest]) -> list[SLACheck]:
        """Check SLAs for multiple requests."""
        all_checks = []
        for request in requests:
            all_checks.extend(self.check_request(request))
        return all_checks

    def get_breached(self, requests: list[TMRequest]) -> list[SLACheck]:
        """Get only breached SLAs."""
        return [c for c in self.check_all(requests) if c.status == SLAStatus.BREACHED]

    def get_at_risk(self, requests: list[TMRequest]) -> list[SLACheck]:
        """Get at-risk SLAs (approaching breach)."""
        return [c for c in self.check_all(requests) if c.status == SLAStatus.AT_RISK]

    def _evaluate(self, key: str, sla_name: str, elapsed: float, target: SLATarget) -> SLACheck:
        """Evaluate a single SLA check."""
        remaining = target.target_hours - elapsed

        if elapsed >= target.target_hours:
            status = SLAStatus.BREACHED
            message = f"SLA breached by {abs(remaining):.1f} hours"
        elif elapsed >= target.warning_hours:
            status = SLAStatus.AT_RISK
            message = f"SLA at risk — {remaining:.1f} hours remaining"
        else:
            status = SLAStatus.ON_TRACK
            message = f"On track — {remaining:.1f} hours remaining"

        return SLACheck(
            request_key=key,
            sla_name=sla_name,
            status=status,
            elapsed_hours=round(elapsed, 1),
            target_hours=target.target_hours,
            remaining_hours=round(remaining, 1),
            message=message,
        )
