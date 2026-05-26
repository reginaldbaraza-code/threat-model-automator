"""Tests for Jira intake processor and state machine."""

import pytest
from src.jira.client import TMRequest, TMStatus, TMPriority
from src.jira.intake import IntakeProcessor, TriageResult
from src.jira.transitions import StateMachine, VALID_TRANSITIONS


# === Intake Tests ===

class TestIntakeTriage:
    @pytest.fixture
    def processor(self):
        # No real Jira client needed for triage logic
        return IntakeProcessor(jira=None, config={})

    def _make_request(self, summary="", description="", **kwargs):
        defaults = dict(
            key="TM-1", summary=summary, description=description,
            status=TMStatus.NEW, priority=TMPriority.MEDIUM,
            reporter="test", assignee=None, created="", updated="", labels=[],
        )
        defaults.update(kwargs)
        return TMRequest(**defaults)

    def test_critical_keywords_raise_priority(self, processor):
        req = self._make_request(
            description="Payment service handles PII and authentication login credentials encryption"
        )
        result = processor.triage(req)
        assert result.suggested_priority in (TMPriority.CRITICAL, TMPriority.HIGH)
        assert len(result.risk_factors) >= 2

    def test_high_keywords_detected(self, processor):
        req = self._make_request(
            description="Customer-facing external API for production database with cloud migration"
        )
        result = processor.triage(req)
        assert result.suggested_priority in (TMPriority.HIGH, TMPriority.MEDIUM)

    def test_low_priority_for_simple_description(self, processor):
        req = self._make_request(description="Internal documentation tool update")
        result = processor.triage(req)
        assert result.suggested_priority == TMPriority.LOW

    def test_internet_facing_boosts_priority(self, processor):
        req = self._make_request(
            description="Simple service",
            is_internet_facing=True,
        )
        result = processor.triage(req)
        assert len(result.risk_factors) >= 1

    def test_compliance_scope_boosts_priority(self, processor):
        req = self._make_request(
            description="Data service",
            compliance_scope=["SOC2", "GDPR"],
        )
        result = processor.triage(req)
        assert any("SOC2" in f for f in result.risk_factors)

    def test_duration_estimate_reasonable(self, processor):
        req = self._make_request(description="Simple web app")
        result = processor.triage(req)
        assert 1.0 <= result.estimated_duration_hours <= 4.0

    def test_complex_system_longer_duration(self, processor):
        req = self._make_request(
            description="Microservice distributed system with new architecture migration"
        )
        result = processor.triage(req)
        assert result.estimated_duration_hours >= 2.0


# === State Machine Tests ===

class TestStateMachine:
    @pytest.fixture
    def sm(self):
        return StateMachine()

    def test_valid_transition_new_to_triaged(self, sm):
        result = sm.can_transition(TMStatus.NEW, TMStatus.TRIAGED)
        assert result.allowed

    def test_invalid_transition_new_to_closed(self, sm):
        result = sm.can_transition(TMStatus.NEW, TMStatus.CLOSED)
        assert not result.allowed

    def test_guard_requires_assignee_for_scheduling(self, sm):
        result = sm.can_transition(
            TMStatus.TRIAGED, TMStatus.SCHEDULED,
            context={"scheduled_date": "2026-06-01"},
        )
        assert not result.allowed
        assert any("assignee" in g for g in result.failed_guards)

    def test_guard_passes_with_assignee_and_date(self, sm):
        result = sm.can_transition(
            TMStatus.TRIAGED, TMStatus.SCHEDULED,
            context={"assignee": "alice", "scheduled_date": "2026-06-01"},
        )
        assert result.allowed

    def test_guard_requires_findings_reviewed_for_close(self, sm):
        result = sm.can_transition(
            TMStatus.REVIEW, TMStatus.CLOSED,
            context={"unreviewed_findings": 3},
        )
        assert not result.allowed

    def test_close_allowed_when_findings_reviewed(self, sm):
        result = sm.can_transition(
            TMStatus.REVIEW, TMStatus.CLOSED,
            context={"unreviewed_findings": 0},
        )
        assert result.allowed

    def test_cancel_from_any_non_terminal(self, sm):
        for status in [TMStatus.NEW, TMStatus.TRIAGED, TMStatus.SCHEDULED, TMStatus.IN_PROGRESS]:
            result = sm.can_transition(status, TMStatus.CANCELLED)
            assert result.allowed, f"Should be able to cancel from {status.value}"

    def test_cannot_transition_from_closed(self, sm):
        available = sm.get_available_transitions(TMStatus.CLOSED)
        assert len(available) == 0

    def test_review_can_bounce_back(self, sm):
        result = sm.can_transition(TMStatus.REVIEW, TMStatus.IN_PROGRESS)
        assert result.allowed
