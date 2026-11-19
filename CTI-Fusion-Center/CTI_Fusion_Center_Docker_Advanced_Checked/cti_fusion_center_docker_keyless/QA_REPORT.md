# CTI Fusion Center — QA review

## Checks completed in this environment

- `python -m py_compile app.py scheduler.py`: PASS
- `docker-compose.yml` parsed with PyYAML: PASS
- Expected Compose services (`mongo`, `dashboard`, `scheduler`): PRESENT
- MongoDB health check: PRESENT
- Dashboard health check: PRESENT and checks Streamlit's `/_stcore/health`
- Scheduler no longer inherits the Streamlit-only Dockerfile health check: FIXED
- Duplicate static Streamlit widget keys: NONE FOUND
- Duplicate `report_year` widget key: FIXED
- Dashboard enhancements: severity distribution chart, IOC count by source chart, collapsible daily sync activity chart, updated analyst-console styling
- `.env` excluded from Docker build context: PASS

## Checks not possible here

- Docker image build / `docker compose up`: not run because Docker Engine/CLI is not installed in this environment.
- MongoDB integration test: not run because there is no running MongoDB service here and `pymongo`/`streamlit` are not installed in the current test runtime.
- Live source checks: attempted, but outbound DNS/network access is unavailable in this environment. Therefore, OpenPhish, CTI Digest, CISA KEV, and Feodo Tracker endpoint availability is not certified by this review.

## Local verification commands

Run from the extracted project directory in PowerShell:

```powershell
python -m py_compile app.py scheduler.py
docker compose config
docker compose up --build -d
docker compose ps
docker compose logs --tail=100 scheduler
docker compose logs --tail=100 dashboard
```

Open `http://localhost:8501` after the dashboard reports healthy. Verify each source's status in **Overview** and **Source Connectors**. If a feed fails, its error should be recorded and the other sources should continue.
