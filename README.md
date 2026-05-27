# Threat Model Automator 🤖

Automates the operational side of running a threat modeling service — the Jira ticket handling, session scheduling, findings tracking, and metrics reporting that eat up time between actual threat model sessions.

## The Problem

Running a threat modeling service at scale involves a lot of manual coordination:

- A new request lands in Jira → someone has to read it, assess priority, assign it
- A session needs scheduling → someone checks calendars, sends invites, writes an agenda
- After the session → someone logs findings, sets deadlines, tracks remediation
- Management asks for metrics → someone pulls data from three different tools

This project automates those workflows so the security team can focus on the threat modeling itself, not the admin around it.

## How It Works

```
Jira (requests) ──▶ Automator Engine ──▶ Calendar (scheduling)
                        │
                    AI Triage ──▶ Findings DB (tracking)
                        │
                        └──▶ FastAPI Dashboard (metrics)
```

**Jira lifecycle** (`src/jira/`): Watches for new TM requests, auto-triages them based on keywords (payment, PII, authentication → higher priority), enforces a status workflow with guard conditions, and monitors SLA compliance.

**Calendar scheduling** (`src/calendar/`): Finds available slots across team members, generates session agendas with a standard 4-section format (architecture review → STRIDE analysis → risk assessment → action items), and handles conflicts.

**Findings management** (`src/findings/`): SQLite-backed database for tracking findings from assessments. Each finding has a severity, DREAD score, owner, due date, and status (Open → Acknowledged → Remediated → Verified). Includes a metrics module for dashboard summaries.

**AI triage** (`src/agents/`): LLM-powered request classification for edge cases where keyword matching isn't enough. Estimates session duration, suggests focus areas, and identifies relevant STRIDE categories. Falls back gracefully when the API is unavailable.

## Quick Start

```bash
git clone https://github.com/reginaldbaraza-code/threat-model-automator.git
cd threat-model-automator
pip install -e ".[dev]"

# Run all 27 tests
pytest -v

# Start the dashboard
uvicorn src.dashboard:app --reload

# Copy and edit the config
cp config.yaml.example config.yaml
```

## Configuration

Edit `config.yaml` with your Jira server, team email addresses, and SLA targets. See `config.yaml.example` for all available options. The AI triage agent reads the `ANTHROPIC_API_KEY` environment variable.

## Project Structure

```
threat-model-automator/
├── src/
│   ├── jira/
│   │   ├── client.py         # Jira API wrapper (TMRequest, TMStatus, TMPriority)
│   │   ├── intake.py         # Auto-triage with keyword scoring
│   │   ├── transitions.py    # State machine with guards
│   │   └── sla.py            # SLA monitoring (per-priority targets)
│   ├── calendar/
│   │   └── scheduler.py      # Slot finder + session agenda generator
│   ├── findings/
│   │   ├── models.py         # SQLAlchemy models (Assessment, Finding)
│   │   ├── repository.py     # CRUD + query operations
│   │   └── metrics.py        # Dashboard summary calculations
│   ├── agents/
│   │   └── triage.py         # LLM triage agent (Anthropic API)
│   └── dashboard.py          # FastAPI: /api/metrics, /findings, /assessments, /sla
├── tests/
│   ├── test_intake_transitions.py   # 16 tests: triage scoring + state machine
│   └── test_sla_scheduling.py       # 11 tests: SLA checks + calendar scheduling
├── config.yaml.example
└── pyproject.toml
```

## Tech Stack

- **Python 3.11+**, **FastAPI**, **SQLAlchemy**, **Anthropic SDK**, **pytest** (27 tests)

## License

MIT
