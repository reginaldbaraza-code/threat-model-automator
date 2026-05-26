"""
AI-powered triage agent for threat model requests.

Uses an LLM to analyze incoming TM requests and provide:
- Priority classification
- Scope estimation
- Session agenda pre-population
- Complexity assessment

The agent augments (not replaces) the rule-based triage in
intake.py, providing natural language analysis for edge cases
where keyword matching falls short.

Usage:
    agent = TriageAgent(api_key="...")
    result = agent.classify_request(request_description)
"""

from dataclasses import dataclass
from typing import Optional


TRIAGE_SYSTEM_PROMPT = """You are a security engineer specializing in threat modeling.
Your job is to analyze incoming threat model requests and provide triage recommendations.

For each request, assess:
1. PRIORITY (Critical / High / Medium / Low) based on:
   - Data sensitivity (PII, financial, health data → higher)
   - Internet exposure (public-facing → higher)
   - Compliance scope (SOC2, GDPR, PCI → higher)
   - Attack surface complexity

2. ESTIMATED DURATION (in hours, 1.0 to 4.0):
   - Simple web app: 1.0-1.5h
   - Standard microservice: 1.5-2.0h
   - Complex distributed system: 2.0-3.0h
   - Critical infrastructure: 3.0-4.0h

3. KEY AREAS TO FOCUS on during the threat model session

4. PRELIMINARY THREATS to investigate (STRIDE categories most relevant)

Respond in JSON format:
{
  "priority": "High",
  "estimated_hours": 2.0,
  "focus_areas": ["authentication flow", "data encryption"],
  "relevant_stride": ["Spoofing", "Information Disclosure"],
  "complexity": "medium",
  "rationale": "Brief explanation of triage decision"
}"""


@dataclass
class TriageAnalysis:
    """Result from AI triage analysis."""

    priority: str
    estimated_hours: float
    focus_areas: list[str]
    relevant_stride: list[str]
    complexity: str
    rationale: str
    raw_response: str = ""


class TriageAgent:
    """
    LLM-powered triage agent for threat model requests.

    Uses the Anthropic API to analyze request descriptions
    and provide intelligent triage recommendations.

    In production, this would call the Anthropic API.
    This implementation provides the interface and prompt
    engineering for integration.
    """

    def __init__(self, api_key: str = "", model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
        self._client = None

        if api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                pass

    def classify_request(
        self,
        description: str,
        service_name: str = "",
        additional_context: str = "",
    ) -> TriageAnalysis:
        """
        Analyze a TM request and return triage recommendations.

        Args:
            description: The request description from Jira.
            service_name: Name of the service to be threat-modeled.
            additional_context: Any extra context (labels, team, etc.).

        Returns:
            TriageAnalysis with priority, duration estimate, and focus areas.
        """
        prompt = self._build_prompt(description, service_name, additional_context)

        if self._client:
            return self._call_api(prompt)
        else:
            # Fallback: return a reasonable default
            return self._fallback_analysis(description)

    def _build_prompt(
        self,
        description: str,
        service_name: str,
        additional_context: str,
    ) -> str:
        """Build the prompt for the LLM."""
        parts = [f"Threat Model Request Analysis\n"]

        if service_name:
            parts.append(f"Service: {service_name}")

        parts.append(f"Description:\n{description}")

        if additional_context:
            parts.append(f"\nAdditional Context:\n{additional_context}")

        parts.append("\nProvide your triage analysis in JSON format.")
        return "\n".join(parts)

    def _call_api(self, prompt: str) -> TriageAnalysis:
        """Call the Anthropic API for analysis."""
        import json

        response = self._client.messages.create(
            model=self.model,
            max_tokens=1000,
            system=TRIAGE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text

        try:
            # Extract JSON from response
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            import re
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if match:
                data = json.loads(match.group())
            else:
                return self._fallback_analysis("")

        return TriageAnalysis(
            priority=data.get("priority", "Medium"),
            estimated_hours=data.get("estimated_hours", 1.5),
            focus_areas=data.get("focus_areas", []),
            relevant_stride=data.get("relevant_stride", []),
            complexity=data.get("complexity", "medium"),
            rationale=data.get("rationale", ""),
            raw_response=raw,
        )

    @staticmethod
    def _fallback_analysis(description: str) -> TriageAnalysis:
        """Provide a conservative default when API is unavailable."""
        return TriageAnalysis(
            priority="Medium",
            estimated_hours=1.5,
            focus_areas=["Authentication", "Data flow encryption", "Access controls"],
            relevant_stride=["Spoofing", "Information Disclosure", "Elevation of Privilege"],
            complexity="medium",
            rationale="Default triage — API unavailable. Manual review recommended.",
        )
