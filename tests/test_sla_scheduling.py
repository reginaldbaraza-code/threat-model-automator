"""Tests for SLA monitoring and calendar scheduling."""

import pytest
from datetime import datetime, timedelta

from src.jira.client import TMRequest, TMStatus, TMPriority
from src.jira.sla import SLAMonitor, SLAStatus
from src.calendar.scheduler import SessionScheduler, TimeSlot, SessionAgenda


# === SLA Tests ===

class TestSLAMonitor:
    @pytest.fixture
    def monitor(self):
        return SLAMonitor()

    def _make_request(self, status, priority, hours_ago):
        created = (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat()
        return TMRequest(
            key="TM-1", summary="Test", description="",
            status=status, priority=priority,
            reporter="test", assignee=None,
            created=created, updated=created, labels=[],
        )

    def test_new_request_on_track(self, monitor):
        req = self._make_request(TMStatus.NEW, TMPriority.MEDIUM, hours_ago=1)
        checks = monitor.check_request(req)
        response_check = next(c for c in checks if c.sla_name == "response")
        assert response_check.status == SLAStatus.ON_TRACK

    def test_new_request_breached(self, monitor):
        req = self._make_request(TMStatus.NEW, TMPriority.MEDIUM, hours_ago=72)
        checks = monitor.check_request(req)
        response_check = next(c for c in checks if c.sla_name == "response")
        assert response_check.status == SLAStatus.BREACHED

    def test_critical_has_shorter_sla(self, monitor):
        req = self._make_request(TMStatus.NEW, TMPriority.CRITICAL, hours_ago=5)
        checks = monitor.check_request(req)
        response_check = next(c for c in checks if c.sla_name == "response")
        assert response_check.status == SLAStatus.BREACHED  # Critical: 4h SLA

    def test_resolution_sla_tracked(self, monitor):
        req = self._make_request(TMStatus.IN_PROGRESS, TMPriority.MEDIUM, hours_ago=10)
        checks = monitor.check_request(req)
        assert any(c.sla_name == "resolution" for c in checks)

    def test_closed_no_sla_checks(self, monitor):
        req = self._make_request(TMStatus.CLOSED, TMPriority.MEDIUM, hours_ago=100)
        checks = monitor.check_request(req)
        assert len(checks) == 0

    def test_get_breached_filters(self, monitor):
        requests = [
            self._make_request(TMStatus.NEW, TMPriority.CRITICAL, hours_ago=10),
            self._make_request(TMStatus.NEW, TMPriority.LOW, hours_ago=1),
        ]
        breached = monitor.get_breached(requests)
        assert len(breached) >= 1


# === Scheduler Tests ===

class TestSessionScheduler:
    @pytest.fixture
    def scheduler(self):
        return SessionScheduler(config={"session_duration_minutes": 90})

    def test_find_slot(self, scheduler):
        # Start search from a known Monday
        monday = datetime(2026, 6, 1, 10, 0)  # Monday 10 AM
        slot = scheduler.find_next_available(
            team_members=["alice@corp.com"],
            requestor="bob@corp.com",
            after=monday,
        )
        assert slot is not None
        assert slot.duration_minutes == 90
        assert len(slot.attendees) == 2

    def test_avoids_busy_slots(self, scheduler):
        monday = datetime(2026, 6, 1, 10, 0)
        busy = [
            TimeSlot(start=monday, end=monday + timedelta(hours=2)),
        ]
        slot = scheduler.find_next_available(
            team_members=["alice@corp.com"],
            requestor="bob@corp.com",
            after=monday,
            busy_slots=busy,
        )
        assert slot is not None
        assert slot.start >= monday + timedelta(hours=2)

    def test_skips_weekends(self, scheduler):
        saturday = datetime(2026, 5, 30, 10, 0)  # Saturday
        slot = scheduler.find_next_available(
            team_members=["alice@corp.com"],
            requestor="bob@corp.com",
            after=saturday,
        )
        assert slot is not None
        assert slot.start.weekday() < 5  # Monday-Friday


class TestSessionAgenda:
    def test_default_agenda(self):
        agenda = SessionAgenda.default_agenda("Payment Service", "TM-42")
        assert agenda.service_name == "Payment Service"
        assert agenda.jira_key == "TM-42"
        assert len(agenda.sections) == 4
        assert agenda.duration_minutes == 90

    def test_agenda_to_text(self):
        agenda = SessionAgenda.default_agenda("API Gateway", "TM-10")
        text = agenda.to_text()
        assert "API Gateway" in text
        assert "TM-10" in text
        assert "STRIDE" in text
