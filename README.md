<![CDATA[<div align="center">

# Cortex Management Server

**Fleet management for CortexOS nodes.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![Version](https://img.shields.io/badge/version-0.5.1-green.svg)](package.json)
[![Node.js](https://img.shields.io/badge/Node.js-22+-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)

Monitor, manage, and control your entire [CortexOS Server](https://github.com/ivanuser/cortex-server-os) fleet from a single dashboard.
Generate install tokens, auto-register nodes, chat with any server's AI, and respond to incidents — all from one place.

</div>

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│            Management Dashboard (SPA)             │
│            http://localhost:9443                   │
├──────────────────────────────────────────────────┤
│                                                    │
│   Express.js API (/api/v1/)                        │
│   ├─ Auth (JWT + TOTP 2FA)                         │
│   ├─ Fleet (servers, tokens, health)               │
│   ├─ Incident Response (auto-detect + remediate)   │
│   ├─ Scheduled Operations (cron-style)             │
│   ├─ Server Templates (web, db, docker, etc.)      │
│   ├─ Webhooks (Slack, Discord, Teams, custom)      │
│   └─ Audit Log (every action tracked)              │
│                                                    │
│   SQLite (better-sqlite3) — zero-config storage    │
│                                                    │
│   WebSocket Proxy — chat/terminal relay to nodes   │
│                                                    │
├──────────────┬─────────────┬─────────────────────┤
│ Health Poller│  Incident   │   Scheduler          │
│   (30s)      │  Monitor    │   (cron-style)       │
└──────┬───────┴──────┬──────┴──────────┬──────────┘
       │              │                 │
  ┌────▼───┐    ┌─────▼──┐       ┌─────▼──┐
  │Server 1│    │Server 2│  ...  │Server N│
  │CortexOS│    │CortexOS│       │CortexOS│
  └────────┘    └────────┘       └────────┘
```

---

## Quick Start

### Bare Metal

```bash
# Clone & install
git clone https://github.com/ivanuser/cortex-management-server.git
cd cortex-management-server
npm install

# Start (production)
npm start

# Start (dev mode with auto-reload)
npm run dev
```

### Docker

```bash
docker compose up -d
```

### Install as systemd Service

```bash
sudo bash scripts/install-management.sh
```

Installs Node.js if needed, runs `npm install`, creates a `cortex-management` systemd service, and enables auto-start on boot.

**Dashboard:** http://localhost:9443/dashboard/

---

## Default Credentials

| Field | Value |
|-------|-------|
| **Username** | `admin` |
| **Password** | `admin` |

> ⚠️ **Change the default password immediately after first login.** Enable 2FA from the user settings panel.

---

## Features

| Feature | Description |
|---------|-------------|
| 🖥️ **Fleet Dashboard** | Server cards with live CPU / RAM / disk bars, color-coded health status |
| 💬 **Embedded Server Management** | Chat with any server's AI, manage skills, run terminal — all from the management UI |
| 🔐 **Auth with 2FA** | JWT sessions + optional TOTP two-factor authentication |
| 👥 **User Management** | Admin, operator, viewer roles — create, deactivate, role assignment |
| 📋 **Server Templates** | Pre-configured profiles (web server, database, Docker host, etc.) — one-click provisioning |
| 🎟️ **Install Tokens** | Generate one-time tokens for auto-registering new CortexOS nodes |
| 📊 **Health Monitoring** | 30-second polling with full snapshot history and trend charts |
| 🚨 **Incident Response** | Auto-detect critical conditions (high CPU, disk full, offline) and trigger remediation |
| 📅 **Scheduled Operations** | Cron-style scheduled commands across the fleet (updates, backups, audits) |
| 🔔 **Webhooks** | Push notifications to Slack, Discord, Teams, or any URL on server events |
| 💾 **Centralized Backups** | Agent state backups stored in the management database |
| 📈 **Analytics** | Fleet-wide resource trends and utilization metrics |
| 📝 **Audit Log** | Every action — logins, server changes, token generation — logged with user + IP |
| 🔌 **WebSocket Proxy** | Relay chat and terminal sessions from browser → management server → CortexOS node |

---

## Fleet Management Workflow

```
1. Generate Token          2. Install CortexOS          3. Auto-Register
┌─────────────────┐       ┌──────────────────────┐     ┌──────────────────┐
│ Management UI   │       │ Target Server         │     │ Management Server│
│ → Add Server    │──────▶│ curl install.sh       │────▶│ ← POST /register│
│ → Generate Token│       │ --token=ctx_srv_XXX   │     │ → Store server   │
│ → Copy command  │       │ --management-url=...  │     │ → Start polling  │
└─────────────────┘       └──────────────────────┘     └──────────────────┘
                                                              │
                                                              ▼
                                                        Visible in fleet
                                                        dashboard in ~30s
```

**Step by step:**

1. **Generate token** — In the management dashboard, click "Add Server" and generate an install token
2. **Install on target** — Run the one-liner on the new server:
   ```bash
   curl -sO https://mgmt.example.com/install.sh?token=ctx_srv_XXXXX && sudo bash install.sh
   ```
3. **Auto-register** — The installer calls the management API, registers the server, and starts health reporting
4. **Manage** — The new server appears in the fleet dashboard with live stats, chat, terminal, and skills

Install tokens are **one-time use** and can have expiration dates.

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/login` | Login → JWT token (supports 2FA) |
| `POST` | `/api/v1/auth/logout` | Logout / invalidate session |
| `GET` | `/api/v1/auth/me` | Current user info |
| `PUT` | `/api/v1/auth/password` | Change password |
| `POST` | `/api/v1/auth/2fa/setup` | Generate TOTP secret + QR |
| `POST` | `/api/v1/auth/2fa/verify` | Verify & enable 2FA |
| `POST` | `/api/v1/auth/2fa/disable` | Disable 2FA |
| `GET` | `/api/v1/auth/users` | List users (admin only) |
| `POST` | `/api/v1/auth/users` | Create user (admin only) |
| `DELETE` | `/api/v1/auth/users/:id` | Deactivate user (admin only) |

### Fleet Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/servers` | List all servers + latest health |
| `POST` | `/api/v1/servers` | Add server manually |
| `GET` | `/api/v1/servers/:id` | Server detail |
| `DELETE` | `/api/v1/servers/:id` | Remove server |
| `GET` | `/api/v1/servers/:id/health` | Health snapshot history |
| `POST` | `/api/v1/servers/register` | Register via install token |

### Install Tokens

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/tokens` | Generate install token |
| `GET` | `/api/v1/tokens` | List active tokens |
| `DELETE` | `/api/v1/tokens/:id` | Revoke token |

### Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/incidents` | List incidents |
| `GET` | `/api/v1/scheduled-ops` | List scheduled operations |
| `POST` | `/api/v1/scheduled-ops` | Create scheduled operation |
| `GET` | `/api/v1/webhooks` | List webhooks |
| `POST` | `/api/v1/webhooks` | Create webhook |
| `GET` | `/api/v1/templates` | List server templates |
| `POST` | `/api/v1/templates/:id/apply` | Apply template to server |
| `GET` | `/api/v1/audit` | Audit log (admin only) |

---

## Server Templates

Pre-built server profiles for common use cases:

| Template | Description | Skills Installed |
|----------|-------------|-----------------|
| 🌍 **Web Server** | Nginx reverse proxy with SSL and hardening | nginx, certbot, security-hardening, firewall-manager |
| 🐘 **Database Server** | PostgreSQL + Redis with automated backups | postgres, redis, backup-manager, security-hardening |
| 🐳 **Docker Host** | Docker engine with compose and monitoring | docker-manager, docker-compose, monitoring |
| 🔒 **Security Node** | Hardened bastion with audit logging | security-hardening, firewall-manager, user-manager |

Templates run setup commands on the target server through its AI agent — skills are installed and configured automatically.

---

## Webhook Events

Configure webhooks to receive notifications on:

| Event | Trigger |
|-------|---------|
| `server_offline` | Server stops responding to health polls |
| `server_online` | Server comes back online |
| `incident_critical` | Critical incident detected (CPU >95%, disk >95%) |
| `incident_warning` | Warning-level incident (high memory, service down) |
| `backup_complete` | Agent backup completed |
| `scheduled_op_complete` | Scheduled operation finished |

Webhooks support any HTTP endpoint — Slack, Discord, Teams, PagerDuty, or custom.

---

## Configuration

Config is auto-generated on first run at `data/config.json`:

```json
{
  "jwtSecret": "<auto-generated-64-char-hex>",
  "port": 9443
}
```

**Database:** `data/cortex-management.db` (SQLite via better-sqlite3 — zero external dependencies).

**Environment variables (Docker):**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9443` | Server listen port |
| `JWT_SECRET` | auto-generated | JWT signing secret |
| `ADMIN_PASSWORD` | `admin` | Initial admin password |
| `NODE_ENV` | `production` | Environment mode |
| `DATA_DIR` | `./data` | Database and config directory |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Runtime** | Node.js 22+ (ESM) |
| **Server** | Express.js |
| **Database** | SQLite via better-sqlite3 |
| **Auth** | bcryptjs + jsonwebtoken + otplib (TOTP) |
| **Real-time** | WebSocket (ws) — health polling + chat/terminal proxy |
| **Dashboard** | Single HTML file (no build step, no framework) |
| **Container** | Docker + Docker Compose |

---

## Project Structure

```
cortex-management-server/
├── src/
│   ├── server.js              # Express + WebSocket server
│   ├── auth/
│   │   ├── routes.js          # Auth API (login, 2FA, users)
│   │   └── middleware.js      # JWT verification, role guards
│   ├── fleet/
│   │   ├── routes.js          # Fleet API (servers, tokens, ops)
│   │   ├── health-poller.js   # 30s health snapshot collector
│   │   ├── incident-response.js # Auto-detect + remediate
│   │   ├── scheduler.js       # Cron-style operation scheduler
│   │   ├── templates.js       # Server template engine
│   │   ├── templates.json     # Built-in template definitions
│   │   └── webhooks.js        # Webhook dispatch system
│   └── db/
│       └── init.js            # SQLite schema + migrations
├── dashboard/
│   └── index.html             # Fleet management SPA
├── scripts/
│   └── install-management.sh  # systemd service installer
├── data/                      # Runtime data (SQLite DB, config)
├── Dockerfile                 # Production Docker image
├── docker-compose.yml         # Docker Compose config
└── package.json
```

---

## Contributing

Contributions are welcome! Fork the repo, create a branch, make your changes, and open a PR.

**Areas where help is most valuable:**
- Dashboard UX — charts, fleet visualizations, dark/light themes
- Additional server templates
- Webhook integrations (PagerDuty, OpsGenie, etc.)
- Test coverage
- Documentation and guides

---

## License

[MIT](https://opensource.org/licenses/MIT)

---

## Links

- 🖥️ [CortexOS Server](https://github.com/ivanuser/cortex-server-os) — The AI-managed server node this manages
- 🧩 [CortexOS Skills](https://github.com/ivanuser/cortex-server-skills) — 35+ extended skill packs
- 📖 [Roadmap](https://github.com/ivanuser/cortex-server-os/blob/main/ROADMAP.md) — Full project roadmap

---

<div align="center">

**Cortex Management Server** — One dashboard to manage them all.

Built by [@ivanuser](https://github.com/ivanuser)

</div>
]]>