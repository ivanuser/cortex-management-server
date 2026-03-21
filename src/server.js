import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import path from 'path';
import { config } from './db/init.js';
import authRoutes from './auth/routes.js';
import fleetRoutes from './fleet/routes.js';
import { startHealthPoller } from './fleet/health-poller.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = config.port || 9443;

// ─── Middleware ─────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

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
  
  try {
    // Try to fetch latest installer from GitHub
    const response = await fetch('https://raw.githubusercontent.com/ivanuser/cortex-server-os/main/install.sh');
    if (!response.ok) throw new Error('Failed to fetch installer');
    let script = await response.text();
    
    // Inject management server config at the top
    const mgmtConfig = `
# ─── Management Server Configuration (auto-injected) ────────
MANAGEMENT_URL="${mgmtUrl}"
MANAGEMENT_TOKEN="${mgmtToken}"
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

// ─── Start ──────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║       CortexOS Management Server v0.3.0       ║
╠═══════════════════════════════════════════════╣
║  Dashboard: http://localhost:${PORT}/dashboard/  ║
║  API:       http://localhost:${PORT}/api/v1/     ║
║  Default:   admin / admin                     ║
╚═══════════════════════════════════════════════╝
  `);
  startHealthPoller();
});

export default app;
