"""
Auto-scheduling engine for threat model sessions.

Finds available time slots across TM team members and requestors,
creates calendar events with pre-populated agendas, and handles
rescheduling.

Usage:
    scheduler = SessionScheduler(config)
    slot = scheduler.find_next_available(
        team_members=["alice@corp.com", "bob@corp.com"],
        requestor="charlie@corp.com",
        duration_minutes=90,
    )
    scheduler.create_session(slot, tm_request)
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional


class SlotStatus(Enum):
    AVAILABLE = "available"
    TENTATIVE = "tentative"
    BOOKED = "booked"


@dataclass
class TimeSlot:
    """A proposed time slot for a TM session."""

    start: datetime
    end: datetime
    attendees: list[str] = field(default_factory=list)
    status: SlotStatus = SlotStatus.AVAILABLE
    room: str = ""
    video_link: str = ""

    @property
    def duration_minutes(self) -> int:
        return int((self.end - self.start).total_seconds() / 60)


@dataclass
class SessionAgenda:
    """Pre-populated agenda for a TM session."""

    title: str
    service_name: str
    jira_key: str
    duration_minutes: int
    sections: list[dict] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [
            f"# Threat Model Session: {self.service_name}",
            f"**Jira:** {self.jira_key}",
            f"**Duration:** {self.duration_minutes} minutes",
            "",
        ]
        for section in self.sections:
            lines.append(f"## {section['title']} ({section['duration']} min)")
            if section.get("description"):
                lines.append(section["description"])
            lines.append("")
        return "\n".join(lines)

    @classmethod
    def default_agenda(cls, service_name: str, jira_key: str, duration: int = 90) -> "SessionAgenda":
        """Create a standard TM session agenda."""
        return cls(
            title=f"Threat Model: {service_name}",
            service_name=service_name,
            jira_key=jira_key,
            duration_minutes=duration,
            sections=[
                {
                    "title": "System Overview & Architecture",
                    "duration": 20,
                    "description": (
                        "Walk through the system architecture, components, "
                        "data flows, and trust boundaries."
                    ),
                },
                {
                    "title": "STRIDE Analysis",
                    "duration": 40,
                    "description": (
                        "Systematic analysis of each component and data flow "
                        "against all six STRIDE categories."
                    ),
                },
                {
                    "title": "Risk Assessment & Prioritization",
                    "duration": 15,
                    "description": (
                        "Score identified threats using DREAD. "
                        "Agree on severity and remediation priorities."
                    ),
                },
                {
                    "title": "Mitigations & Action Items",
                    "duration": 15,
                    "description": (
                        "Define mitigation strategies. Assign owners "
                        "and deadlines for each finding."
                    ),
                },
            ],
        )


class SessionScheduler:
    """
    Finds available slots and creates TM session calendar events.

    In production, this integrates with Outlook/Google Calendar APIs.
    This implementation provides the scheduling logic and data structures.
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.default_duration = self.config.get("session_duration_minutes", 90)
        self.buffer_minutes = self.config.get("buffer_minutes", 15)
        self.working_hours = (9, 17)  # 9 AM to 5 PM
        self.working_days = (0, 1, 2, 3, 4)  # Mon-Fri

    def find_next_available(
        self,
        team_members: list[str],
        requestor: str,
        duration_minutes: int = None,
        after: datetime = None,
        busy_slots: list[TimeSlot] = None,
    ) -> Optional[TimeSlot]:
        """
        Find the next available time slot for all participants.

        Args:
            team_members: Email addresses of TM team members.
            requestor: Email of the person requesting the TM.
            duration_minutes: Session duration (default from config).
            after: Earliest acceptable start time (default: now + 48h).
            busy_slots: Known busy times for participants.

        Returns:
            A TimeSlot if found, None if no slots available in the next 2 weeks.
        """
        duration = duration_minutes or self.default_duration
        if after is None:
            after = datetime.utcnow() + timedelta(hours=48)

        busy = set()
        if busy_slots:
            for slot in busy_slots:
                busy.add((slot.start, slot.end))

        # Scan the next 14 days for an available slot
        candidate = self._next_working_time(after)
        end_search = after + timedelta(days=14)

        while candidate < end_search:
            slot_end = candidate + timedelta(minutes=duration)

            # Check if within working hours
            if slot_end.hour > self.working_hours[1]:
                candidate = self._next_working_time(
                    candidate.replace(hour=self.working_hours[0], minute=0) + timedelta(days=1)
                )
                continue

            # Check for conflicts
            conflicts = any(
                not (slot_end <= busy_start or candidate >= busy_end)
                for busy_start, busy_end in busy
            )

            if not conflicts:
                all_attendees = team_members + [requestor]
                return TimeSlot(
                    start=candidate,
                    end=slot_end,
                    attendees=all_attendees,
                    status=SlotStatus.TENTATIVE,
                )

            # Move to next slot (30-minute increments)
            candidate += timedelta(minutes=30)

        return None

    def _next_working_time(self, dt: datetime) -> datetime:
        """Advance to the next working hour if needed."""
        while dt.weekday() not in self.working_days:
            dt = dt.replace(hour=self.working_hours[0], minute=0) + timedelta(days=1)

        if dt.hour < self.working_hours[0]:
            dt = dt.replace(hour=self.working_hours[0], minute=0)
        elif dt.hour >= self.working_hours[1]:
            dt = (dt + timedelta(days=1)).replace(hour=self.working_hours[0], minute=0)
            while dt.weekday() not in self.working_days:
                dt += timedelta(days=1)

        return dt
