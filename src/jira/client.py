"""
Jira API client wrapper for threat model request management.

Provides a typed interface over the Jira REST API focused on
threat modeling workflow operations: creating, querying, and
transitioning TM request tickets.

Usage:
    client = JiraClient.from_config(config)
    requests = client.get_open_requests()
    client.transition(issue_key="TM-42", to_status=TMStatus.SCHEDULED)
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

import httpx


class TMStatus(Enum):
    """Threat model request lifecycle states."""

    NEW = "New"
    TRIAGED = "Triaged"
    SCHEDULED = "Scheduled"
    IN_PROGRESS = "In Progress"
    REVIEW = "Review"
    CLOSED = "Closed"
    CANCELLED = "Cancelled"


class TMPriority(Enum):
    """Request priority levels (maps to Jira priority)."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class TMRequest:
    """A parsed threat model request from Jira."""

    key: str
    summary: str
    description: str
    status: TMStatus
    priority: TMPriority
    reporter: str
    assignee: Optional[str]
    created: str
    updated: str
    labels: list[str]
    service_name: str = ""
    data_classification: str = ""
    is_internet_facing: bool = False
    compliance_scope: list[str] = None

    def __post_init__(self):
        if self.compliance_scope is None:
            self.compliance_scope = []


class JiraClient:
    """
    Jira client for threat modeling request management.

    Wraps the Jira REST API with methods specific to the TM workflow:
    - Query open requests by status
    - Transition tickets through the TM lifecycle
    - Update fields (priority, assignee, labels)
    - Add comments for audit trail

    In production this uses the `jira` Python SDK; here we use
    httpx for a lighter dependency footprint in examples.
    """

    def __init__(self, server: str, email: str, api_token: str, project_key: str = "TM"):
        self.server = server.rstrip("/")
        self.project_key = project_key
        self._client = httpx.Client(
            base_url=f"{self.server}/rest/api/3",
            auth=(email, api_token),
            headers={"Content-Type": "application/json"},
            timeout=30.0,
        )

    @classmethod
    def from_config(cls, config: dict) -> "JiraClient":
        """Create a client from a config dictionary."""
        jira_cfg = config.get("jira", {})
        return cls(
            server=jira_cfg["server"],
            email=jira_cfg["email"],
            api_token=jira_cfg["api_token"],
            project_key=jira_cfg.get("project_key", "TM"),
        )

    def get_open_requests(self, status: Optional[TMStatus] = None) -> list[TMRequest]:
        """
        Fetch open TM requests from Jira.

        Args:
            status: Filter by specific status. If None, returns all non-Closed.

        Returns:
            List of parsed TMRequest objects.
        """
        if status:
            jql = f'project = {self.project_key} AND status = "{status.value}"'
        else:
            jql = (
                f'project = {self.project_key} AND status NOT IN '
                f'("{TMStatus.CLOSED.value}", "{TMStatus.CANCELLED.value}")'
            )

        response = self._client.get(
            "/search",
            params={"jql": jql, "maxResults": 100, "fields": "summary,description,status,priority,reporter,assignee,created,updated,labels"},
        )
        response.raise_for_status()
        data = response.json()

        return [self._parse_issue(issue) for issue in data.get("issues", [])]

    def transition(self, issue_key: str, to_status: TMStatus, comment: str = "") -> None:
        """
        Transition a Jira issue to a new status.

        Args:
            issue_key: The Jira issue key (e.g., "TM-42").
            to_status: Target status.
            comment: Optional comment to add with the transition.
        """
        # First get available transitions
        resp = self._client.get(f"/issue/{issue_key}/transitions")
        resp.raise_for_status()
        transitions = resp.json().get("transitions", [])

        target = next(
            (t for t in transitions if t["name"] == to_status.value),
            None,
        )
        if not target:
            available = [t["name"] for t in transitions]
            raise ValueError(
                f"Cannot transition {issue_key} to '{to_status.value}'. "
                f"Available transitions: {available}"
            )

        payload = {"transition": {"id": target["id"]}}
        if comment:
            payload["update"] = {
                "comment": [{"add": {"body": {"type": "doc", "version": 1,
                    "content": [{"type": "paragraph",
                        "content": [{"type": "text", "text": comment}]}]}}}]
            }

        resp = self._client.post(f"/issue/{issue_key}/transitions", json=payload)
        resp.raise_for_status()

    def update_priority(self, issue_key: str, priority: TMPriority) -> None:
        """Update the priority of a Jira issue."""
        resp = self._client.put(
            f"/issue/{issue_key}",
            json={"fields": {"priority": {"name": priority.value}}},
        )
        resp.raise_for_status()

    def add_comment(self, issue_key: str, text: str) -> None:
        """Add a comment to a Jira issue."""
        body = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph",
                    "content": [{"type": "text", "text": text}]}],
            }
        }
        resp = self._client.post(f"/issue/{issue_key}/comment", json=body)
        resp.raise_for_status()

    def assign(self, issue_key: str, account_id: str) -> None:
        """Assign a Jira issue to a user."""
        resp = self._client.put(
            f"/issue/{issue_key}/assignee",
            json={"accountId": account_id},
        )
        resp.raise_for_status()

    def _parse_issue(self, issue: dict) -> TMRequest:
        """Parse a Jira issue JSON into a TMRequest."""
        fields = issue.get("fields", {})
        status_name = fields.get("status", {}).get("name", "New")
        priority_name = fields.get("priority", {}).get("name", "Medium")

        try:
            status = TMStatus(status_name)
        except ValueError:
            status = TMStatus.NEW

        try:
            priority = TMPriority(priority_name)
        except ValueError:
            priority = TMPriority.MEDIUM

        description = ""
        desc_field = fields.get("description")
        if desc_field and isinstance(desc_field, dict):
            # ADF format — extract text nodes
            description = self._extract_adf_text(desc_field)
        elif isinstance(desc_field, str):
            description = desc_field

        return TMRequest(
            key=issue["key"],
            summary=fields.get("summary", ""),
            description=description,
            status=status,
            priority=priority,
            reporter=fields.get("reporter", {}).get("displayName", "Unknown"),
            assignee=fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
            created=fields.get("created", ""),
            updated=fields.get("updated", ""),
            labels=fields.get("labels", []),
        )

    @staticmethod
    def _extract_adf_text(adf: dict) -> str:
        """Recursively extract text from Atlassian Document Format."""
        texts = []
        for node in adf.get("content", []):
            if node.get("type") == "text":
                texts.append(node.get("text", ""))
            elif "content" in node:
                texts.append(JiraClient._extract_adf_text(node))
        return " ".join(texts)
