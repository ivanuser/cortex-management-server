import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import path from 'path';
import { URL } from 'url';
import jwt from 'jsonwebtoken';
import { WebSocketServer, WebSocket } from 'ws';
import { db, config } from './db/init.js';
import authRoutes from './auth/routes.js';
import fleetRoutes from './fleet/routes.js';
import { startHealthPoller } from './fleet/health-poller.js';
import { startIncidentMonitor } from './fleet/incident-response.js';
import { startScheduler } from './fleet/scheduler.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = config.port || 9443;

// ─── Middleware ─────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

// Simple cookie parser (avoid extra dependency)
app.use((req, _res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(c => {
      const [key, ...vals] = c.trim().split('=');
      if (key) req.cookies[key] = vals.join('=');
    });
  }
  next();
});

// Trust proxy for correct req.ip behind reverse proxy
app.set('trust proxy', true);

// ─── API Routes ─────────────────────────────────────────────
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1', fleetRoutes);

// ─── Dashboard Static Files ────────────────────────────────
const dashboardDir = path.join(__dirname, '..', 'dashboard');
app.use('/dashboard', express.static(dashboardDir));

// Redirect root to dashboard
app.get('/', (_req, res) => {
  res.redirect('/dashboard/');
});

// Dashboard SPA fallback
app.get('/dashboard/*', (_req, res) => {
  res.sendFile(path.join(dashboardDir, 'index.html'));
});

// ─── Install Script Endpoint ────────────────────────────────
// Serves the CortexOS Server installer with management URL pre-configured
app.get('/install.sh', async (req, res) => {
  const mgmtToken = req.query.token || '';
  const mgmtUrl = `${req.protocol}://${req.get('host')}`;
  
  // Look up token config for API key
  let apiProvider = '';
  let apiKey = '';
  if (mgmtToken) {
    try {
      const tokenRow = db.prepare('SELECT config FROM install_tokens WHERE token = ?').get(mgmtToken);
      if (tokenRow?.config) {
        const cfg = JSON.parse(tokenRow.config);
        apiProvider = cfg.provider || '';
        apiKey = cfg.api_key || '';
      }
    } catch {}
  }
  
  try {
    // Try to fetch latest installer from GitHub
    const response = await fetch('https://raw.githubusercontent.com/ivanuser/cortex-server-os/main/install.sh');
    if (!response.ok) throw new Error('Failed to fetch installer');
    let script = await response.text();
    
    // Inject management server config — these override the defaults in the script
    const mgmtConfig = `
# ─── Management Server Configuration (auto-injected) ────────
export MGMT_URL="${mgmtUrl}"
export MGMT_TOKEN="${mgmtToken}"
export MGMT_API_PROVIDER="${apiProvider}"
export MGMT_API_KEY="${apiKey}"
# ─────────────────────────────────────────────────────────────
`;
    script = script.replace('set -euo pipefail', 'set -euo pipefail\n' + mgmtConfig);
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(script);
  } catch (err) {
    // Fallback: redirect to GitHub raw
    res.redirect(`https://raw.githubusercontent.com/ivanuser/cortex-server-os/main/install.sh`);
  }
});

// ─── 404 Handler ────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ─── Error Handler ──────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start (HTTP server + WebSocket proxy) ─────────────────
import { createServer } from 'http';
const server = createServer(app);

// ─── WebSocket Proxy ────────────────────────────────────────
// Proxies browser WS connections to target server gateways,
// solving mixed-content (wss:// → ws://) issues.
// Path: /api/v1/ws/proxy/:serverId?jwt=TOKEN
// ─────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  // Parse the URL to check if it's our proxy path
  const parsed = new URL(req.url, `http://${req.headers.host}`);
  const match = parsed.pathname.match(/^\/api\/v1\/ws\/proxy\/([^/]+)$/);

  if (!match) {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }

  const serverId = match[1];
  const jwtToken = parsed.searchParams.get('jwt');

  if (!jwtToken) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  // Verify JWT
  let user;
  try {
    const payload = jwt.verify(jwtToken, config.jwtSecret);
    user = db.prepare(
      'SELECT id, username, role, active FROM users WHERE id = ?'
    ).get(payload.userId);
    if (!user || !user.active) throw new Error('User inactive');
  } catch (err) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  // Look up the target server
  const targetServer = db.prepare(
    'SELECT id, name, gateway_url, gateway_token FROM servers WHERE id = ?'
  ).get(serverId);

  if (!targetServer || !targetServer.gateway_url) {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }

  // Accept the upgrade
  wss.handleUpgrade(req, socket, head, (browserWs) => {
    wss.emit('connection', browserWs, req, targetServer, user);
  });
});

wss.on('connection', (browserWs, req, targetServer, user) => {
  const gwUrl = targetServer.gateway_url.replace(/^http/, 'ws').replace(/\/$/, '');
  let gatewayWs = null;
  let browserClosed = false;
  let gatewayClosed = false;

  console.log(`[WS Proxy] ${user.username} → ${targetServer.name} (${gwUrl})`);

  // Open connection to the target gateway
  try {
    gatewayWs = new WebSocket(gwUrl, {
      headers: {
        'Origin': `http://${targetServer.gateway_url.replace(/^https?:\/\//, '').replace(/\/$/, '')}`,
      }
    });
  } catch (err) {
    console.error(`[WS Proxy] Failed to create WS to ${gwUrl}:`, err.message);
    browserWs.close(1011, 'Failed to connect to gateway');
    return;
  }

  // Gateway connection opened — start relaying
  gatewayWs.on('open', () => {
    console.log(`[WS Proxy] Connected to gateway: ${targetServer.name}`);
  });

  // Relay: Gateway → Browser
  gatewayWs.on('message', (data, isBinary) => {
    if (browserWs.readyState === WebSocket.OPEN) {
      browserWs.send(data, { binary: isBinary });
    }
  });

  // Relay: Browser → Gateway
  browserWs.on('message', (data, isBinary) => {
    if (gatewayWs.readyState === WebSocket.OPEN) {
      gatewayWs.send(data, { binary: isBinary });
    }
  });

  // Close handling
  browserWs.on('close', (code, reason) => {
    browserClosed = true;
    console.log(`[WS Proxy] Browser disconnected (${targetServer.name}): ${code}`);
    if (!gatewayClosed && gatewayWs.readyState !== WebSocket.CLOSED) {
      gatewayWs.close(1000, 'Browser disconnected');
    }
  });

  gatewayWs.on('close', (code, reason) => {
    gatewayClosed = true;
    console.log(`[WS Proxy] Gateway disconnected (${targetServer.name}): ${code}`);
    if (!browserClosed && browserWs.readyState !== WebSocket.CLOSED) {
      browserWs.close(1000, 'Gateway disconnected');
    }
  });

  // Error handling
  browserWs.on('error', (err) => {
    console.error(`[WS Proxy] Browser WS error (${targetServer.name}):`, err.message);
  });

  gatewayWs.on('error', (err) => {
    console.error(`[WS Proxy] Gateway WS error (${targetServer.name}):`, err.message);
    if (!browserClosed && browserWs.readyState !== WebSocket.CLOSED) {
      browserWs.close(1011, 'Gateway connection error');
    }
  });
});

server.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║       CortexOS Management Server v0.6.1       ║
╠═══════════════════════════════════════════════╣
║  Dashboard: http://localhost:${PORT}/dashboard/  ║
║  API:       http://localhost:${PORT}/api/v1/     ║
║  WS Proxy:  ws://localhost:${PORT}/api/v1/ws/proxy/:id ║
║  Default:   admin / admin                     ║
╚═══════════════════════════════════════════════╝
  `);
  startHealthPoller();
  startIncidentMonitor();
  startScheduler();
});

export default app;
