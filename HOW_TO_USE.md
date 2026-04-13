# SecurityScarletAI — How to Use

A complete guide for running and using SecurityScarletAI as a new user.

---

## Quick Start

### 1. Start Infrastructure (Docker)

```bash
# Start Docker runtime (Colima on macOS)
colima start

# Navigate to project
cd ~/Security\ Apps/SecurityScarletAI

# Start PostgreSQL and Redis
docker-compose up -d
```

**What this does:** Launches the database (PostgreSQL + TimescaleDB) and cache (Redis) in Docker containers.

---

### 2. Start the API (Backend)

Open a terminal and run:

```bash
cd ~/Security\ Apps/SecurityScarletAI

# Install dependencies (first time only)
poetry install

# Start the API server
poetry run uvicorn src.api.main:app --reload
```

**What this does:** Starts the FastAPI server on `http://localhost:8000`

You will see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

**Important:** Leave this terminal running. This is the backend.

---

### 3. Start the Dashboard (Frontend)

Open a **new terminal window** (keep the API running):

```bash
cd ~/Security\ Apps/SecurityScarletAI

# Start the web dashboard
poetry run streamlit run dashboard/main.py
```

**What this does:** Opens the Streamlit dashboard on `http://localhost:8501`

You will see:
```
You can now view your Streamlit app in your browser.
URL: http://127.0.0.1:8501
```

**Important:** Leave this terminal running too.

---

### 4. Verify Ollama (AI Engine)

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags
```

**What this does:** Confirms the AI models are available for analysis.

---

## Dashboard Pages

Open **http://localhost:8501** in your browser.

---

### Page 1: Overview (Home)

**What you see:**
- Total events ingested today
- Active alerts count
- System health status
- Event volume graph

**What you do:**
- Monitor from this command center
- Click through to other pages for details

---

### Page 2: Logs View

**What you see:**
- Raw security events from all sources
- Columns: timestamp, host, source, event type, severity

**What you do:**

Send a test log from terminal:
```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Authorization: Bearer bedd3171c0cf5a095e5ab6acc28c202257688340a7ff5874e0bf97d61cc624d1" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "@timestamp": "2026-04-09T20:00:00Z",
      "host_name": "my-laptop",
      "source": "manual",
      "event_category": "authentication",
      "event_type": "login",
      "severity": "info",
      "user": "raphael",
      "result": "success"
    }
  ]'
```

In dashboard:
- Filter by time range
- Search for specific hosts or users
- Export to CSV

---

### Page 3: Alerts View

**What you see:**
- Triggered security alerts
- Severity: Low, Medium, High, Critical
- Status: New, Acknowledged, Resolved

**How alerts are created:**
1. Logs flow into the system
2. Sigma rules run pattern matching
3. Matches become alerts

**What you do:**
- Click an alert to see details
- **Acknowledge** — "I saw this, investigating"
- **Assign** — Give to someone
- **Resolve** — False positive or fixed
- **Escalate** — Create a case

---

### Page 4: Cases View

**What you see:**
- Security incidents (grouped related alerts)
- Investigation timeline
- Evidence collected

**What you do:**
- Create case from alert
- Add notes
- Attach evidence
- Track resolution status

**Example workflow:**
```
Alert: "Brute force attack detected"
  ↓
Create Case: "Investigate brute force from IP 192.168.1.100"
  ↓
Collect Evidence: logs, screenshots
  ↓
Response: Block IP via firewall
  ↓
Resolve Case
```

---

### Page 5: Rules View

**What you see:**
- Sigma detection rules (YAML files)
- Rule status: Enabled/Disabled
- Hit count (how many times triggered)

**What you do:**

Create a new rule:
```bash
# See available rules
ls ~/Security\ Apps/SecurityScarletAI/rules/

# Create a custom rule
cat > ~/Security\ Apps/SecurityScarletAI/rules/my_custom_rule.yml << 'EOF'
title: Suspicious Process Execution
logsource:
  category: process
detection:
  selection:
    - Image|contains: 'mimikatz'
    - CommandLine|contains: 'sekurlsa'
  condition: selection
falsepositives:
  - Unknown
level: critical
EOF
```

In dashboard:
- Enable/disable rules
- View rule details
- See detection history

---

## Terminal Commands Reference

### Daily Startup

```bash
# Terminal 1: Start infrastructure
colima start
cd ~/Security\ Apps/SecurityScarletAI
docker-compose up -d

# Terminal 2: Start API
cd ~/Security\ Apps/SecurityScarletAI
poetry run uvicorn src.api.main:app --reload

# Terminal 3: Start dashboard
cd ~/Security\ Apps/SecurityScarletAI
poetry run streamlit run dashboard/main.py
```

### Database Queries

```bash
# Check logs count
docker exec -it scarletai-db psql -U scarletai -d scarletai -c "SELECT COUNT(*) FROM logs;"

# See recent alerts
docker exec -it scarletai-db psql -U scarletai -d scarletai -c "SELECT * FROM alerts ORDER BY time DESC LIMIT 5;"

# Check detection rules
docker exec -it scarletai-db psql -U scarletai -d scarletai -c "SELECT * FROM rules;"
```

### API Health Check

```bash
# Test everything is working
curl http://localhost:8000/api/v1/health
```

### Send Test Data (Generate Fake Attack)

```bash
cd ~/Security\ Apps/SecurityScarletAI
poetry run python scripts/generate_attack_data.py --scenario all
```

---

## Typical Workflow

### As a security analyst using SecurityScarletAI:

1. **Morning:** Open dashboard, check overnight alerts
2. **Investigate:** Click alerts → view logs → understand what happened
3. **Respond:** Acknowledge real threats, dismiss false positives
4. **Create cases** for anything needing follow-up
5. **Review rules** — tune detection to reduce noise

### Example scenario:

```
08:00 — Check dashboard: 3 new alerts overnight
08:05 — Alert 1: "Failed login attempts" → Check logs → 50 attempts from 1 IP
08:10 — Create case, block IP in firewall
08:15 — Alert 2: "Process injection detected" → Investigate → False positive
08:20 — Dismiss alert, update rule to exclude this process
08:25 — Alert 3: "Malware hash match" → High priority → Escalate
```

---

## Service Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| Dashboard | http://localhost:8501 | Web interface |
| API Docs | http://localhost:8000/docs | Swagger/OpenAPI |
| API Health | http://localhost:8000/api/v1/health | Status check |
| Ollama | http://localhost:11434 | AI models |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6379 | Cache |

---

## Troubleshooting

### Services won't start

```bash
# Check Docker is running
colima status

# Check containers
docker ps

# View logs
docker-compose logs
```

### API won't connect

```bash
# Check if port is in use
lsof -i :8000

# Kill process if needed
kill -9 <PID>
```

### Dashboard not loading

```bash
# Check Streamlit is running on correct port
curl http://localhost:8501
```

---

## Key Features

| Feature | Description |
|---------|-------------|
| Real-time ingestion | See attacks as they happen |
| AI analysis | LLM explains alerts in plain English |
| MITRE ATT&CK mapping | Understand attacker techniques |
| Case management | Track investigations end-to-end |
| Response automation | Block threats automatically |

---

## FAQ

**Q: Do I need to know SQL?**  
A: No — the dashboard handles everything. But SQL helps for custom queries.

**Q: Where does data come from?**  
A: osquery (endpoint logs), API (manual sends), file tail (application logs)

**Q: Can I add my own detection rules?**  
A: Yes — write Sigma YAML files in the `rules/` folder

**Q: What if I stop the terminals?**  
A: Services stop. Restart with the same commands.

---

## Next Steps

- Simulate an attack and detect it
- Create a custom detection rule
- Investigate an alert
- Set up osquery on your Mac

---

Document version: 1.0  
Last updated: April 9, 2026
