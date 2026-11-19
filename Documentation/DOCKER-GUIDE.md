# Docker Guide

Docker is used in multiple labs and both major applications. Keep Docker commands scoped to the directory containing the relevant Compose file.

## Main application commands

### Chatbot
```powershell
cd .\Chatbot\LLM_Threat_Chat_App
docker compose up --build
```

### CTI Fusion Center
```powershell
cd .\CTI-Fusion-Center\CTI_Fusion_Center_Docker_Advanced_Checked\cti_fusion_center_docker_keyless
docker compose up --build
```

## Lab commands

Labs with Docker Compose retain their original Compose files. Open the lab directory and follow its local README. Examples include Labs 8, 9, 10, 11, 12, 13, 15, 16, and 18.

## Useful commands

```powershell
docker compose up --build       # Build images and start services
docker compose ps               # Show service status
docker compose logs -f          # Follow logs
docker compose down              # Stop and remove containers/networks
```

Do not run multiple lab Compose projects simultaneously unless their ports, container names, and networks have been checked for conflicts.
