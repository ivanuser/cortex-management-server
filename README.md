# CortexOS Management Server

**Fleet management for CortexOS Server instances.**

Centralized dashboard to manage multiple CortexOS servers from one place. Monitor health, chat with any server's AI, run fleet-wide commands, and manage access — all from a single URL.

## Architecture

```
Management Server (port 9443)
├── Express.js API + JWT Auth + TOTP 2FA
├── SQLite Database (users, servers, health, audit)
├── WebSocket Proxy (browser → server gateways)
├── Health Poller (30s interval)
├── Incident Response (auto-remediation)
├── Scheduler (cron-based fleet operations)
├── Webhooks (Discord/Slack notifications)
│
├── Server A (192.168.1.88:18789) → Nadia
├── Server B (192.168.1.72:18789) → Discourse
└── Server C ...
```

## Quick Start

```bash
# Clone & install
git clone https://github.com/ivanuser/cortex-management-server.git
cd cortex-management-server
npm install
npm start
```

Dashboard: `http://localhost:9443/dashboard/`
Default login: **admin / admin**

### Docker

```bash
git clone https://github.com/ivanuser/cortex-management-server.git
cd cortex-management-server
docker compose up -d
```

### Systemd Service

```bash
sudo bash scripts/install-management.sh
```

## Features

- **Fleet Dashboard** — Grid of server cards with live CPU/RAM/disk stats
- **Embedded Server Management** — Chat, skills, terminal, health for each server — no separate URLs
- **Auth + 2FA** — Username/password with optional TOTP (Google Authenticator compatible)
- **User Roles** — Admin, Operator, Viewer with granular permissions
- **Server Templates** — Web Server, Database, Docker Host, Full Stack, Monitoring presets
- **Install Tokens** — Generate tokens that auto-register servers on install
- **Health Monitoring** — 30-second polling with online/offline detection
- **Incident Response** — Auto-detects high CPU/RAM/disk, sends remediation commands
- **Scheduled Operations** — Cron-based commands across fleet
- **Webhook Notifications** — Discord/Slack alerts for server events
- **Centralized Backups** — Backup agent state from any server
- **Analytics** — Fleet-wide stats, per-server trends, incident breakdown
- **Audit Log** — All actions logged with user, timestamp, details
- **WebSocket Proxy** — Solves HTTPS/HTTP mixed content for server communication
- **Server Editing** — Update names, agent names, gateway URLs from the dashboard

## Fleet Management Workflow

```
1. Install Management Server
   npm start (or docker compose up -d)

2. Login → Add Server → Generate Token
   → Copies install command with baked-in token + API key

3. Run on new server:
   curl -sSL "https://mgmt.example.com/install.sh?token=TOKEN" | sudo bash

4. Server auto-installs, auto-registers, appears in fleet dashboard
   Health reporting starts within 30 seconds

5. Click server → Chat with its AI, manage skills, run terminal commands
```

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/login | Login |
| POST | /api/v1/auth/logout | Logout |
| GET | /api/v1/auth/me | Current user |
| PUT | /api/v1/auth/password | Change password |
| POST | /api/v1/auth/2fa/setup | Setup TOTP |
| POST | /api/v1/auth/2fa/verify | Verify & enable 2FA |
| POST | /api/v1/auth/2fa/disable | Disable 2FA |
| GET | /api/v1/auth/users | List users |
| POST | /api/v1/auth/users | Create user |
| PUT | /api/v1/auth/users/:id | Update user |
| DELETE | /api/v1/auth/users/:id | Delete user |

### Fleet
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/servers | List servers |
| POST | /api/v1/servers | Add server |
| GET | /api/v1/servers/:id | Server detail |
| PUT | /api/v1/servers/:id | Update server |
| DELETE | /api/v1/servers/:id | Remove server |
| GET | /api/v1/servers/:id/health | Health history |
| POST | /api/v1/servers/:id/backup | Trigger backup |
| GET | /api/v1/servers/:id/backups | List backups |
| GET | /api/v1/servers/:id/analytics | Server analytics |
| POST | /api/v1/servers/register | Auto-register (installer) |
| POST | /api/v1/fleet/command | Fleet-wide command |

### Tokens
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/tokens | Generate install token |
| GET | /api/v1/tokens | List tokens |
| DELETE | /api/v1/tokens/:id | Revoke token |

### Operations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/schedules | List scheduled ops |
| POST | /api/v1/schedules | Create schedule |
| PUT | /api/v1/schedules/:id | Update schedule |
| DELETE | /api/v1/schedules/:id | Delete schedule |
| GET | /api/v1/webhooks | List webhooks |
| POST | /api/v1/webhooks | Create webhook |
| DELETE | /api/v1/webhooks/:id | Delete webhook |
| GET | /api/v1/incidents | List incidents |
| GET | /api/v1/analytics | Fleet analytics |
| GET | /api/v1/templates | Server templates |

## Server Templates

| Template | Skills Installed |
|----------|-----------------|
| Web Server | nginx, certbot, security-hardening |
| Database | postgres, redis, backup-manager |
| Docker Host | docker-manager, docker-compose |
| Full Stack | nginx, postgres, redis, nodejs, certbot |
| Monitoring | prometheus, grafana |

## Related Repos

- [cortex-server-os](https://github.com/ivanuser/cortex-server-os) — CortexOS Server installer + dashboard
- [cortex-server-skills](https://github.com/ivanuser/cortex-server-skills) — Extended skill packs (35+)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT
