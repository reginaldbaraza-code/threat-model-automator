# Threat Model Automator 🤖

Automate the operational lifecycle of threat modeling services — from Jira request intake to scheduling, assessment tracking, and findings management.

## Problem

Running a threat modeling service at scale involves significant manual overhead:
- Triaging incoming requests from Jira
- Scheduling sessions with engineering teams
- Tracking assessment progress and follow-ups
- Managing findings and remediation timelines
- Reporting on service metrics

This project automates those workflows, reducing operational burden so security teams can focus on the actual threat modeling.

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│  Jira       │───▶│  Automator   │───▶│  Calendar        │
│  (Requests) │    │  Engine      │    │  (Scheduling)    │
└─────────────┘    │              │    └─────────────────┘
                   │  ┌────────┐  │    ┌─────────────────┐
                   │  │ AI     │  │───▶│  Findings DB     │
                   │  │ Triage │  │    │  (Tracking)      │
                   │  └────────┘  │    └─────────────────┘
                   └──────────────┘    ┌─────────────────┐
                          │           ▶│  Dashboard       │
                          └───────────▶│  (FastAPI)       │
                                       └─────────────────┘
```

## Features

### Jira Lifecycle Management (`src/jira/`)
- **Request intake** — Watch a Jira project for new TM requests, auto-assign priority based on data classification, internet exposure, and compliance scope
- **Status transitions** — Automate ticket workflow: `New → Triaged → Scheduled → In Progress → Review → Closed`
- **SLA tracking** — Monitor response/resolution times against SLA targets
- **Bulk operations** — Handle recurring assessments (quarterly re-reviews)

### Calendar Scheduling (`src/calendar/`)
- **Auto-scheduling** — Find available slots across TM team members and requestors
- **Outlook integration** — Create/update calendar invites with pre-populated agendas
- **Conflict resolution** — Handle reschedules and cancellations gracefully
- **Reminder automation** — Send prep reminders 48h before sessions

### Findings Management (`src/findings/`)
- **Findings database** — SQLite-backed store for all identified threats
- **Severity tracking** — DREAD scores, remediation deadlines, owner assignment
- **Status workflow** — `Open → Acknowledged → In Progress → Remediated → Verified`
- **Metrics & reporting** — Mean time to remediate, open findings by severity, team stats

### AI Triage Agent (`src/agents/`)
- **Request classification** — LLM-powered triage of incoming TM requests
- **Priority suggestion** — Analyze request description to suggest priority level
- **Scope estimation** — Estimate session duration based on system complexity
- **Template generation** — Auto-populate TM session agenda from Jira description

## Quick Start

```bash
git clone https://github.com/reginaldbaraza-code/threat-model-automator.git
cd threat-model-automator
pip install -e ".[dev]"

# Configure
cp .env.example .env
# Edit .env with your Jira and calendar credentials

# Run the dashboard
uvicorn src.dashboard:app --reload

# Run the automation engine
python -m src.engine
```

## Configuration

```yaml
# config.yaml
jira:
  server: https://your-org.atlassian.net
  project_key: TM
  request_type: "Threat Model Request"
  sla_response_hours: 24
  sla_resolution_days: 14

calendar:
  provider: outlook  # or google
  tm_team_emails:
    - alice@company.com
    - bob@company.com
  session_duration_minutes: 90
  buffer_minutes: 15

findings:
  database: sqlite:///findings.db
  severity_sla:
    critical: 7   # days to remediate
    high: 30
    medium: 90
    low: 180

agent:
  model: claude-sonnet-4-20250514
  temperature: 0.3
```

## Project Structure

```
threat-model-automator/
├── src/
│   ├── jira/
│   │   ├── client.py        # Jira API wrapper
│   │   ├── intake.py        # Request intake automation
│   │   ├── transitions.py   # Ticket state machine
│   │   └── sla.py           # SLA monitoring
│   ├── calendar/
│   │   ├── scheduler.py     # Auto-scheduling engine
│   │   ├── outlook.py       # Outlook calendar integration
│   │   └── reminders.py     # Reminder automation
│   ├── findings/
│   │   ├── models.py        # SQLAlchemy models
│   │   ├── repository.py    # CRUD operations
│   │   ├── metrics.py       # Service metrics
│   │   └── export.py        # Report generation
│   ├── agents/
│   │   ├── triage.py        # AI triage agent
│   │   └── prompts.py       # LLM prompt templates
│   ├── engine.py            # Main automation loop
│   └── dashboard.py         # FastAPI dashboard
├── tests/
├── docs/
└── config.yaml.example
```

## Tech Stack

- **Python 3.11+**
- **FastAPI** — Dashboard and API
- **SQLAlchemy** — Findings database ORM
- **Jira Python SDK** — Atlassian integration
- **Anthropic SDK** — AI triage agent
- **APScheduler** — Periodic task execution
- **pytest** — Testing

## Relevance

This project demonstrates automation skills directly applicable to **threat modeling service operations**:
- Jira workflow automation (intake, transitions, SLA)
- Calendar scheduling integration
- AI-aided triage and prioritization
- Service metrics and reporting dashboards

## License

MIT
