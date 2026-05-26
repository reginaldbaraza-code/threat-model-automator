"""
Threat Model Service Dashboard.

FastAPI application providing:
- Service metrics overview
- Open findings with filtering
- Assessment history
- SLA status

Run:
    uvicorn src.dashboard:app --reload
"""

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from typing import Optional

app = FastAPI(
    title="Threat Model Service Dashboard",
    description="Operational dashboard for the threat modeling service",
    version="0.1.0",
)


@app.get("/")
async def root():
    """Dashboard home — service health check."""
    return {
        "service": "Threat Model Automator",
        "status": "healthy",
        "version": "0.1.0",
        "endpoints": {
            "metrics": "/api/metrics",
            "findings": "/api/findings",
            "assessments": "/api/assessments",
            "sla": "/api/sla",
        },
    }


@app.get("/api/metrics")
async def get_metrics():
    """
    Get service metrics summary.

    Returns dashboard-ready data including:
    - Total assessments and findings
    - Open/overdue counts
    - Severity and status distributions
    - Remediation rate
    """
    # In production, this queries the actual database
    return {
        "total_assessments": 47,
        "total_findings": 312,
        "open_findings": 23,
        "overdue_findings": 3,
        "findings_by_severity": {
            "Critical": 2,
            "High": 8,
            "Medium": 9,
            "Low": 4,
        },
        "avg_days_to_remediate": 18.5,
        "assessments_this_month": 6,
        "remediation_rate": 92.6,
    }


@app.get("/api/findings")
async def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    owner: Optional[str] = Query(None, description="Filter by owner"),
    overdue: Optional[bool] = Query(None, description="Show only overdue"),
):
    """
    List findings with optional filters.

    Supports filtering by severity, status, owner, and overdue status.
    Results sorted by DREAD score (highest first).
    """
    # In production, queries FindingsRepository
    return {
        "count": 23,
        "filters": {"severity": severity, "status": status, "owner": owner, "overdue": overdue},
        "findings": [
            {
                "id": 1,
                "threat_id": "THR-001",
                "title": "Missing authorization on Order Service",
                "severity": "Critical",
                "dread_score": 42,
                "status": "In Progress",
                "owner": "alice@corp.com",
                "days_open": 5,
                "is_overdue": False,
            },
        ],
    }


@app.get("/api/assessments")
async def get_assessments(
    limit: int = Query(10, ge=1, le=100),
):
    """List recent assessments."""
    return {
        "count": 47,
        "assessments": [
            {
                "id": 47,
                "jira_key": "TM-47",
                "service_name": "Payment Gateway v2",
                "team": "Platform",
                "assessment_date": "2026-05-20",
                "findings_count": 8,
                "critical_count": 1,
            },
        ],
    }


@app.get("/api/sla")
async def get_sla_status():
    """Get current SLA compliance overview."""
    return {
        "compliance_rate": 94.2,
        "breached": 3,
        "at_risk": 5,
        "on_track": 39,
        "breached_items": [
            {
                "request_key": "TM-38",
                "sla_name": "resolution",
                "elapsed_hours": 360,
                "target_hours": 336,
                "message": "SLA breached by 24.0 hours",
            },
        ],
    }
