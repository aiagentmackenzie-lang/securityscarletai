# Air-Gapped Deployment

SecurityScarletAI is **self-hostable and air-gappable**: every component can
run with **zero outbound network egress**, which is the differentiator vs.
SaaS SIEMs (Wazuh Cloud, Elastic Cloud, Microsoft Sentinel) that require
constant cloud connectivity. This is the enterprise / regulated / sovereign
scenario: classified networks, OT/ICS, GDPR-locality constraints, or any
environment where data may not leave the perimeter.

This document is the operational recipe for a no-egress deploy. It assumes
you have already read [`docs/DEPLOYMENT.md`](DEPLOYMENT.md).

---

## What makes it air-gappable

| Component | Air-gapped behaviour |
|-----------|----------------------|
| **LLM (Ollama)** | Runs locally (`OLLAMA_BASE_URL=http://localhost:11434`). The model weights are pulled onto the host once (`ollama pull mistral:7b`) before going dark. No calls to any external LLM API. AI features degrade to template fallbacks if Ollama is down. |
| **Threat intel feeds** | `THREAT_INTEL_ENABLED=false` disables the periodic refresh scheduler and the initial on-boot refresh — **no calls to URLhaus / AbuseIPDB / OTX**. IOC enrichment still matches the **local** `threat_intel` cache (see "Pre-loading IOCs" below). |
| **Sigma corpus** | 100 Sigma rules ship in the repo (`rules/sigma/`) and are compiled to SQL by the on-box parser — no external rule downloads. |
| **GeoIP** | MaxMind GeoLite2 is a local file (`data/GeoLite2-City.mmdb`) copied into the container. No runtime download. |
| **Telemetry** | **None.** SecurityScarletAI has no Sentry/PostHog/analytics/phone-home. There is no usage reporting. |
| **Container images** | Pull the images once on a connected host, then load them into the air-gapped registry with `docker load` / `skopeo copy`. The images do not phone home at runtime. |
| **Updates** | You control them. No auto-update mechanism exists. |

---

## The air-gapped switch

```bash
# .env (air-gapped overlay)
THREAT_INTEL_ENABLED=false
ABUSEIPDB_API_KEY=
OTX_API_KEY=
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b
```

`THREAT_INTEL_ENABLED=false` is the single egress switch:

- `start_threat_intel_scheduler()` returns immediately — no APScheduler job,
  no initial `refresh_all_feeds()` background task.
- **No** HTTP calls to `urlhaus-api.abuse.ch`, `api.abuseipdb.com`, or OTX.
  (URLhaus normally needs no API key and would otherwise call out every 6 h
  plus once on boot — this switch closes that path too.)
- `enrich_ip_with_threat_intel()` still consults the local `threat_intel` table
  first (cache hit → enrichment applied with no egress). The live AbuseIPDB
  fallback only runs when `ABUSEIPDB_API_KEY` is set — leave it empty and no
  live call is ever made.

Leave `ABUSEIPDB_API_KEY` and `OTX_API_KEY` **empty** even with the switch on;
they are the second layer of defense (a key set would still cause a live
per-IP lookup on cache miss).

---

## Pre-loading IOCs (optional)

Air-gapped ≠ no threat intel. Pre-load IOCs while connected, then go dark:

1. While connected, run a normal deploy **with** `THREAT_INTEL_ENABLED=true`
   and your feed keys set. Let the scheduled refresh populate the
   `threat_intel` table.
2. `pg_dump` the `threat_intel` table and ship the dump into the air-gapped
   environment; `psql ... -f` to restore it.
3. On the air-gapped host, set `THREAT_INTEL_ENABLED=false`. Enrichment now
   matches the restored cache. Schedule an offline refresh cadence (re-dump
   and restore on your maintenance window) — the data goes stale, by design,
   the moment you go dark.

Alternatively load your own private intel into `threat_intel` directly
(internal TIP, STIX/TAXII import — see the threat-intel code).

---

## Step-by-step air-gapped deploy

1. **On a connected host**, prepare the artifacts:
   - `docker pull` the images (postgres:17-alpine, redis:7-alpine, the
     SecurityScarletAI API + dashboard images) and `docker save` them, OR
     push them to your air-gapped registry with `skopeo copy`.
   - `ollama pull mistral:7b` on the host that will run Ollama (it caches to
     `~/.ollama/models`).
   - Download the MaxMind GeoLite2-City mmdb (MaxMind account, one-time) and
     place it at `data/GeoLite2-City.mmdb`.
   - Optionally `pg_dump` a populated `threat_intel` table (above).

2. **Transfer** the images, the model, the mmdb, the repo, and the (optional)
   IOC dump into the air-gapped environment via your approved transfer
   mechanism.

3. **On the air-gapped host**, load the images:
   ```bash
   docker load -i scarletai-api.tar
   # ... or pull from your air-gapped registry
   ```

4. Configure `.env` with the air-gapped overlay (above) plus the required
   secrets (`DB_PASSWORD`, `API_SECRET_KEY`, `API_BEARER_TOKEN`). The DSN is
   derived from `DB_*` parts — do not set `DATABASE_URL`
   (see `docs/DEPLOYMENT.md`).

5. Start Ollama on the host (or a co-located box reachable from the API
   container):
   ```bash
   ollama serve &
   ollama list   # confirm mistral:7b is present
   ```

6. Bring up the stack:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```
   The entrypoint applies the schema, seeds demo data, trains the triage /
   UEBA models, creates the admin (password → `data/admin_initial_password`),
   and starts uvicorn. `THREAT_INTEL_ENABLED=false` means the entrypoint does
   **not** fire the threat-intel refresh.

7. **Verify no egress**: with the host firewall set to deny outbound, the
   API should stay healthy. `GET /api/v1/health` returns `degraded` only for
   Ollama if the model is unreachable; threat-intel health reports
   `no_key`/`never_refreshed` (expected — no egress). The dashboard and all
   detection / AI features work against local data.

---

## What you lose air-gapped

- **Fresh threat intel.** IOC feeds go stale the moment you go dark. The
  severity boost on a TI match only fires against the cached / pre-loaded
  IOCs. This is the inherent trade-off; pre-load on a maintenance cadence.
- **Ollama model upgrades.** You run the model version you pulled. Upgrading
  requires re-pulling on a connected host.

## What you keep

- The full 100-rule Sigma corpus, the 7-rule correlation engine, the
  ML triage (CalibratedClassifier + provenance), UEBA (Isolation Forest),
  NL→SQL, AI explain, hunting assistant, case management, alert suppression,
  audit logging, retention, and the dashboard — all on-box, all local.
- The AI layer is the moat: a self-hosted, air-gappable, AI-native SIEM
  reference architecture that a SaaS SIEM cannot offer in a classified /
  no-egress environment.

---

## See also
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — general deployment, env vars,
  retention, audit immutability.
- [`docs/AI.md`](AI.md) — the AI/ML pipeline (Ollama, triage, NL→SQL).
- [`docs/RULES.md`](RULES.md) — the Sigma + correlation rule reference.