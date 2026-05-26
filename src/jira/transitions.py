"""
Threat model request state machine.

Defines valid transitions and guards for the TM request lifecycle.
Prevents invalid state changes and enforces business rules
(e.g., can't close without an assignee, can't schedule without a date).

Lifecycle:
    New → Triaged → Scheduled → In Progress → Review → Closed
                                                      → Cancelled (from any state)
"""

from dataclasses import dataclass, field
from datetime import datetime

from src.jira.client import TMStatus


@dataclass
class TransitionGuard:
    """A condition that must be met for a transition to proceed."""

    name: str
    description: str
    check: callable  # Takes a dict of context, returns (bool, str)


# Valid transitions: source → [allowed destinations]
VALID_TRANSITIONS: dict[TMStatus, list[TMStatus]] = {
    TMStatus.NEW: [TMStatus.TRIAGED, TMStatus.CANCELLED],
    TMStatus.TRIAGED: [TMStatus.SCHEDULED, TMStatus.CANCELLED],
    TMStatus.SCHEDULED: [TMStatus.IN_PROGRESS, TMStatus.CANCELLED],
    TMStatus.IN_PROGRESS: [TMStatus.REVIEW, TMStatus.CANCELLED],
    TMStatus.REVIEW: [TMStatus.CLOSED, TMStatus.IN_PROGRESS],  # Can bounce back
    TMStatus.CLOSED: [],  # Terminal state
    TMStatus.CANCELLED: [],  # Terminal state
}


def _has_assignee(context: dict) -> tuple[bool, str]:
    """Check that the ticket has an assignee."""
    if context.get("assignee"):
        return True, ""
    return False, "Ticket must have an assignee before this transition"


def _has_schedule(context: dict) -> tuple[bool, str]:
    """Check that a session has been scheduled."""
    if context.get("scheduled_date"):
        return True, ""
    return False, "A session must be scheduled before starting"


def _has_findings_reviewed(context: dict) -> tuple[bool, str]:
    """Check that all findings have been reviewed."""
    unreviewed = context.get("unreviewed_findings", 0)
    if unreviewed == 0:
        return True, ""
    return False, f"{unreviewed} findings still need review before closing"


# Guards for specific transitions
TRANSITION_GUARDS: dict[tuple[TMStatus, TMStatus], list[TransitionGuard]] = {
    (TMStatus.TRIAGED, TMStatus.SCHEDULED): [
        TransitionGuard("assignee", "Must have assignee", _has_assignee),
        TransitionGuard("schedule", "Must have date", _has_schedule),
    ],
    (TMStatus.SCHEDULED, TMStatus.IN_PROGRESS): [
        TransitionGuard("assignee", "Must have assignee", _has_assignee),
    ],
    (TMStatus.REVIEW, TMStatus.CLOSED): [
        TransitionGuard("findings", "All findings reviewed", _has_findings_reviewed),
    ],
}


@dataclass
class TransitionResult:
    """Result of attempting a state transition."""

    allowed: bool
    from_status: TMStatus
    to_status: TMStatus
    failed_guards: list[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


class StateMachine:
    """
    Manages TM request state transitions with guard checks.

    Usage:
        sm = StateMachine()
        result = sm.can_transition(
            from_status=TMStatus.TRIAGED,
            to_status=TMStatus.SCHEDULED,
            context={"assignee": "alice", "scheduled_date": "2026-06-01"}
        )
        if result.allowed:
            # proceed with transition
    """

    def can_transition(
        self,
        from_status: TMStatus,
        to_status: TMStatus,
        context: dict = None,
    ) -> TransitionResult:
        """
        Check if a transition is valid and all guards pass.

        Args:
            from_status: Current ticket status.
            to_status: Desired target status.
            context: Dictionary of ticket context for guard evaluation.

        Returns:
            TransitionResult with allowed=True if transition is valid.
        """
        context = context or {}

        # Check if transition is structurally valid
        allowed_targets = VALID_TRANSITIONS.get(from_status, [])
        if to_status not in allowed_targets:
            return TransitionResult(
                allowed=False,
                from_status=from_status,
                to_status=to_status,
                failed_guards=[
                    f"Invalid transition: {from_status.value} → {to_status.value}. "
                    f"Allowed: {[s.value for s in allowed_targets]}"
                ],
            )

        # Check guards
        guards = TRANSITION_GUARDS.get((from_status, to_status), [])
        failures = []

        for guard in guards:
            passed, reason = guard.check(context)
            if not passed:
                failures.append(f"{guard.name}: {reason}")

        return TransitionResult(
            allowed=len(failures) == 0,
            from_status=from_status,
            to_status=to_status,
            failed_guards=failures,
        )

    def get_available_transitions(self, from_status: TMStatus) -> list[TMStatus]:
        """Get all structurally valid transitions from a status."""
        return VALID_TRANSITIONS.get(from_status, [])
