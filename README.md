# CTI-Summaries

A consolidated academic and practical project repository covering MongoDB, database engineering, containerization, Cyber Threat Intelligence (CTI), and an LLM/RAG-based threat intelligence chatbot.

## Repository contents

- **Labs/** — Lab exercises 1–18, including MongoDB fundamentals, schema design, CRUD, aggregation, indexing, replication, write concern, transactions, sharding, security/RBAC, Docker, Kubernetes, monitoring, disaster recovery, multi-tenancy, polyglot persistence, vector search/RAG, and the capstone benchmark. Labs 7 and 8 are grouped in the supplied source material under a combined CTI/replica-set folder.
- **CTI-Fusion-Center/** — CTI Fusion Center implementation, including its Docker-based deployment configuration and supporting documentation.
- **Chatbot/LLM_Threat_Chat_App/** — LLM-powered threat intelligence chat application with backend/frontend components and Docker configuration.
- **Documentation/** — Architecture diagrams and supporting materials.

## Technology areas

- MongoDB and NoSQL data modeling
- Python application development
- Cyber Threat Intelligence (CTI)
- Retrieval-Augmented Generation (RAG) and vector search
- Docker and Docker Compose
- Kubernetes manifests and deployment exercises
- Monitoring, backup, restore, and disaster recovery

## Docker usage

Docker is used across multiple parts of this repository. Each lab or application may have its own Dockerfile and Compose file because the services and dependencies differ.

### 1. LLM Threat Chat App

Open PowerShell in the repository root and run:

```powershell
cd .\Chatbot\LLM_Threat_Chat_App
docker compose up --build
```

To stop the services:

```powershell
docker compose down
```

### 2. CTI Fusion Center

Locate the Compose project under:

`CTI-Fusion-Center/CTI_Fusion_Center_Docker_Advanced_Checked/cti_fusion_center_docker_keyless/`

Then run:

```powershell
cd .\CTI-Fusion-Center\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless
docker compose up --build
```

To stop it:

```powershell
docker compose down
```

### 3. Docker-based lab exercises

Several labs include their own `Dockerfile` and/or `docker-compose*.yml` files. Run Docker Compose from the specific lab directory that contains the Compose file. For example, Lab 10:

```powershell
cd .\Labs\Lab_10_ACID_Transactions
docker compose up --build
```

Check the README or lab instructions in that directory before starting services. Some labs require environment variables, multiple containers, or a specific startup order.

## Prerequisites

- Git
- Python 3.10 or a version specified by the individual lab
- Docker Desktop with Docker Compose
- MongoDB tools where required by an exercise
- Optional: Kubernetes tooling such as `kubectl` for the Kubernetes lab

## Python environment setup

Create a virtual environment inside the particular lab/application directory, rather than committing one to Git:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

If that project has a `requirements.txt`, install its dependencies:

```powershell
pip install -r requirements.txt
```

Use the requirements file located in the specific project directory. Dependencies differ between labs.

## Environment configuration and security

Real `.env` files, private keys, MongoDB keyfiles, certificates containing private keys, virtual environments, caches, and generated backup archives are intentionally excluded from this repository.

Where an `.env.example` file is provided, copy it to `.env` and replace every placeholder with your own local values. Never commit real passwords, tokens, API keys, private certificates, or database keyfiles. Generate fresh credentials and keyfiles for your own deployment. Lab 12 provides an `.env.example` for `LAB12_ADMIN_PASSWORD`; copy it to `.env` and set a strong password before running its Docker Compose project. Lab 18 provides an `.env.example` for `NEO4J_PASSWORD`; copy it to `.env` before starting `docker-compose-threat.yml`.

## Suggested workflow

1. Open the folder for the lab or application you want to run.
2. Read its local README/instructions.
3. Configure its environment variables using the supplied example file, if present.
4. Start Docker Desktop if using Docker.
5. Run the commands documented for that individual project.

## Notes

This repository preserves the supplied lab/application source files and reports while removing local machine artifacts and sensitive configuration. Docker and Kubernetes configuration files are retained. The presence of a Docker configuration does not by itself guarantee that every project has been tested on every machine; follow the local project instructions and adjust environment-specific settings as needed.
