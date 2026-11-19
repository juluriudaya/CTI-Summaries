# CTI Fusion Center — Docker + MongoDB (Keyless Mode)

A Streamlit cyber-threat intelligence analyst console with MongoDB-backed IOC storage, source provenance, cross-source correlation, source health charts, security-report import, and the existing Lab 7.1 / Lab 7.2 workspace.

## Keyless public data sources

The scheduled synchronizer uses four sources without API keys; MalwareBazaar is an optional fifth source for file hashes:

- **OpenPhish Community Feed** — phishing URLs and extracted hostnames (keyless; non-commercial terms apply).
- **MalwareBazaar** — optional file-hash feed; requires a free abuse.ch Auth-Key.
- **CTI Digest** — public website scraper for IOC rows and article links. Its page structure may change, so a failed scrape is logged and retried on the next cycle.
- **CISA KEV** — public Known Exploited Vulnerabilities JSON catalog.
- **Feodo Tracker** — public JSON feed for botnet command-and-control infrastructure.

These are public feeds, not guaranteed SLAs. Availability, rate limits, terms, formats, and content may change. The application does not download malware samples. Treat an indicator as a lead for investigation, not proof of compromise.

## Architecture

- `dashboard`: Streamlit application on port `8501`.
- `scheduler`: independent worker; runs one sync cycle at startup, then repeats every six hours.
- `mongo`: MongoDB database with persistent Docker volume `cti_mongo_data`.

The dashboard and scheduler share the same Docker image. MongoDB is not exposed on the host by default; containers connect using `mongodb://mongo:27017` on the private Compose network.

## Run on Windows with Docker Desktop

1. Install and start Docker Desktop.
2. Extract this project folder.
3. Open PowerShell in the folder containing `docker-compose.yml`.
4. Optional: copy `.env.example` to `.env` and set `DOCKERHUB_USERNAME` to your Docker Hub username. Do not put secrets in the file.
5. Start all services:
   ```powershell
   docker compose up --build -d
   ```
6. Check services:
   ```powershell
   docker compose config
   docker compose ps
   docker compose logs --tail=100 scheduler
   docker compose logs --tail=100 dashboard
   ```
7. Open `http://localhost:8501`.

The scheduler performs its first collection after MongoDB becomes healthy. Collection results and errors are written to MongoDB `cyber_threat_intelligence.sync_log` and to the scheduler container logs. The dashboard health check is configured only for the dashboard service; the scheduler is a separate worker and does not expose the Streamlit health endpoint.

## Publish the image to Docker Hub

1. Create a public or private repository named `cti-fusion-center` on Docker Hub.
2. In PowerShell, log in:
   ```powershell
   docker login
   ```
3. Set your username and build the image:
   ```powershell
   $env:DOCKERHUB_USERNAME = "YOUR_DOCKERHUB_USERNAME"
   docker compose build
   docker compose push dashboard scheduler
   ```
   Replace `YOUR_DOCKERHUB_USERNAME` with your actual Docker Hub username. The dashboard and scheduler use the same image tag, so Compose publishes the shared image. If you prefer explicit commands, use:
   ```powershell
   docker build -t YOUR_DOCKERHUB_USERNAME/cti-fusion-center:latest .
   docker push YOUR_DOCKERHUB_USERNAME/cti-fusion-center:latest
   ```

To pull and run elsewhere, use the published image in `docker-compose.yml` and keep the MongoDB volume on that host. Docker Hub stores the application image, **not your live database contents**.

## Automatic schedule

Default interval is six hours (`21600` seconds). For a short test only, set `SYNC_INTERVAL_SECONDS=300` in `.env` and recreate the scheduler:

```powershell
docker compose up -d --force-recreate scheduler
```

Set it back to `21600` for normal use. Docker restart policies restart containers after an unexpected exit, but the computer/host must be running and connected to the internet for collection to continue.

## MongoDB persistence and reset

MongoDB data is stored in the named volume `cti_mongo_data`. Normal container restarts do not erase it. **Do not run `docker compose down -v` unless you intentionally want to delete the database volume.**

## Troubleshooting

```powershell
docker compose ps
docker compose logs --tail=200 scheduler
docker compose logs --tail=200 dashboard
```

- `SYNC FAILED` for one feed means that feed was unavailable, rate-limited, or returned a changed format. Other feed jobs continue.
- If MongoDB is not healthy, inspect `docker compose logs mongo`.
- Syntax check outside Docker: `python -m py_compile app.py scheduler.py`.
- The app's PDF/security-report features remain available in the dashboard; the container image includes the Python packages listed in `requirements.txt`. The Overview includes severity distribution, source-volume charts, and a collapsible daily synchronization trend derived from MongoDB records.

## Security notes

- No API keys are required for the four scheduled sources.
- `.env` is excluded from the Docker build context and `.gitignore`.
- MongoDB has no authentication configured in this local academic Compose setup and is not published to the host. For an internet-facing production deployment, enable MongoDB authentication, TLS, restricted networking, backups, and secret management before exposing services.


## QA review

See [`QA_REPORT.md`](QA_REPORT.md) for checks completed and the local commands needed for Docker/MongoDB integration verification.


### Optional malware file hashes

To enable MalwareBazaar hash collection, copy `.env.example` to `.env` and set `MALWAREBAZAAR_AUTH_KEY` to your abuse.ch Auth-Key. Leave it blank to run the four keyless feeds only. The OpenPhish Community Feed is for non-commercial use under its terms.
