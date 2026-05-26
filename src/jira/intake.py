"""
Automated intake processor for threat model requests.

Watches for new TM requests in Jira and performs initial triage:
1. Parse request details (service name, data classification, exposure)
2. Auto-assign priority based on risk factors
3. Add triage comment with findings
4. Transition to Triaged status

Usage:
    intake = IntakeProcessor(jira_client, config)
    intake.process_new_requests()
"""

from dataclasses import dataclass

from src.jira.client import JiraClient, TMRequest, TMStatus, TMPriority


@dataclass
class TriageResult:
    """Result of automated triage analysis."""

    suggested_priority: TMPriority
    risk_factors: list[str]
    estimated_duration_hours: float
    notes: str


class IntakeProcessor:
    """
    Processes new TM requests through automated triage.

    Risk scoring factors:
    - Data classification (restricted/confidential = higher priority)
    - Internet exposure (internet-facing = higher priority)
    - Compliance scope (SOC2, GDPR, PCI = higher priority)
    - Service criticality keywords in description
    """

    CRITICAL_KEYWORDS = [
        "payment", "authentication", "login", "pii", "financial",
        "health", "hipaa", "pci", "gdpr", "credential", "encryption",
        "key management", "certificate", "admin", "root",
    ]

    HIGH_KEYWORDS = [
        "api", "external", "customer-facing", "production",
        "database", "storage", "cloud", "migration",
    ]

    def __init__(self, jira: JiraClient, config: dict = None):
        self.jira = jira
        self.config = config or {}
        self.sla_response_hours = self.config.get("sla_response_hours", 24)

    def process_new_requests(self) -> list[TriageResult]:
        """
        Process all new (untriaged) TM requests.

        Returns a list of TriageResult objects for each processed request.
        """
        new_requests = self.jira.get_open_requests(status=TMStatus.NEW)
        results = []

        for request in new_requests:
            result = self.triage(request)
            self._apply_triage(request, result)
            results.append(result)

        return results

    def triage(self, request: TMRequest) -> TriageResult:
        """
        Analyze a TM request and produce a triage result.

        Scoring:
        - Start at 0 points
        - +3 for each critical keyword found
        - +1 for each high keyword found
        - +5 for internet-facing
        - +5 for restricted data classification
        - +3 for confidential data classification
        - +3 for each compliance framework in scope

        Priority mapping:
        - 15+ points → Critical
        - 10-14 → High
        - 5-9 → Medium
        - 0-4 → Low
        """
        score = 0
        risk_factors = []
        description_lower = (request.description + " " + request.summary).lower()

        # Check keywords
        for keyword in self.CRITICAL_KEYWORDS:
            if keyword in description_lower:
                score += 3
                risk_factors.append(f"Critical keyword: '{keyword}'")

        for keyword in self.HIGH_KEYWORDS:
            if keyword in description_lower:
                score += 1
                risk_factors.append(f"High keyword: '{keyword}'")

        # Check data classification
        if request.data_classification == "restricted":
            score += 5
            risk_factors.append("Restricted data classification")
        elif request.data_classification == "confidential":
            score += 3
            risk_factors.append("Confidential data classification")

        # Check internet exposure
        if request.is_internet_facing or "internet" in description_lower or "external" in description_lower:
            score += 5
            risk_factors.append("Internet-facing service")

        # Check compliance scope
        for framework in request.compliance_scope:
            score += 3
            risk_factors.append(f"In scope for {framework}")

        # Determine priority
        if score >= 15:
            priority = TMPriority.CRITICAL
        elif score >= 10:
            priority = TMPriority.HIGH
        elif score >= 5:
            priority = TMPriority.MEDIUM
        else:
            priority = TMPriority.LOW

        # Estimate duration based on complexity signals
        duration = self._estimate_duration(description_lower, score)

        return TriageResult(
            suggested_priority=priority,
            risk_factors=risk_factors,
            estimated_duration_hours=duration,
            notes=f"Auto-triage score: {score}. {len(risk_factors)} risk factors identified.",
        )

    def _apply_triage(self, request: TMRequest, result: TriageResult) -> None:
        """Apply triage results to the Jira ticket."""
        # Update priority
        self.jira.update_priority(request.key, result.suggested_priority)

        # Add triage comment
        factors_text = "\n".join(f"  • {f}" for f in result.risk_factors)
        comment = (
            f"🤖 **Automated Triage**\n\n"
            f"Priority: {result.suggested_priority.value}\n"
            f"Estimated duration: {result.estimated_duration_hours}h\n\n"
            f"Risk factors:\n{factors_text}\n\n"
            f"{result.notes}"
        )
        self.jira.add_comment(request.key, comment)

        # Transition to Triaged
        self.jira.transition(
            request.key,
            TMStatus.TRIAGED,
            comment=f"Auto-triaged with priority {result.suggested_priority.value}",
        )

    @staticmethod
    def _estimate_duration(description: str, risk_score: int) -> float:
        """Estimate session duration in hours based on complexity."""
        base = 1.5  # Standard 90-minute session

        # Complex systems need more time
        if any(kw in description for kw in ["microservice", "distributed", "multi-tenant"]):
            base += 0.5
        if any(kw in description for kw in ["migration", "redesign", "new architecture"]):
            base += 0.5
        if risk_score >= 15:
            base += 0.5

        return min(base, 4.0)  # Cap at half-day
