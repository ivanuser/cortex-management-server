import { Router } from 'express';
import crypto from 'crypto';
import { db } from '../db/init.js';
import { authenticate, requireRole } from '../auth/middleware.js';

const router = Router();

// Helper to log audit events
function audit(userId, action, details, ip, serverId = null) {
  db.prepare(
    'INSERT INTO audit_log (id, user_id, server_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), userId, serverId, action, details, ip);
}

// ─── Servers ────────────────────────────────────────────────

/**
 * GET /api/v1/servers — list all servers with latest health snapshot
 */
router.get('/servers', authenticate, (req, res) => {
  const servers = db.prepare(`
    SELECT s.*,
      h.cpu_percent, h.memory_used_mb, h.memory_total_mb,
      h.disk_used_gb, h.disk_total_gb, h.disk_percent, h.uptime,
      h.recorded_at AS health_recorded_at
    FROM servers s
    LEFT JOIN health_snapshots h ON h.id = (
      SELECT h2.id FROM health_snapshots h2
      WHERE h2.server_id = s.id
      ORDER BY h2.recorded_at DESC LIMIT 1
    )
    ORDER BY s.name
  `).all();

  res.json(servers);
});

/**
 * GET /api/v1/servers/:id — server detail
 */
router.get('/servers/:id', authenticate, (req, res) => {
  const server = db.prepare(`
    SELECT s.*,
      h.cpu_percent, h.memory_used_mb, h.memory_total_mb,
      h.disk_used_gb, h.disk_total_gb, h.disk_percent, h.uptime,
      h.recorded_at AS health_recorded_at
    FROM servers s
    LEFT JOIN health_snapshots h ON h.id = (
      SELECT h2.id FROM health_snapshots h2
      WHERE h2.server_id = s.id
      ORDER BY h2.recorded_at DESC LIMIT 1
    )
    WHERE s.id = ?
  `).get(req.params.id);

  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  res.json(server);
});

/**
 * POST /api/v1/servers — manually add a server
 */
router.post('/servers', authenticate, requireRole('admin'), (req, res) => {
  const { name, hostname, ip_address, gateway_url, gateway_token, agent_name, tags } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Server name required' });
  }

  const id = crypto.randomUUID();
  db.prepare(`
    INSERT INTO servers (id, name, hostname, ip_address, gateway_url, gateway_token, agent_name, status, registered_by, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'unknown', ?, ?)
  `).run(id, name, hostname || null, ip_address || null, gateway_url || null,
    gateway_token || null, agent_name || null, req.user.id, JSON.stringify(tags || []));

  audit(req.user.id, 'server_added', `Added server: ${name}`, req.ip, id);
  res.status(201).json({ id, name });
});

/**
 * DELETE /api/v1/servers/:id — remove a server
 */
router.delete('/servers/:id', authenticate, requireRole('admin'), (req, res) => {
  const server = db.prepare('SELECT name FROM servers WHERE id = ?').get(req.params.id);
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  db.prepare('DELETE FROM servers WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'server_removed', `Removed server: ${server.name}`, req.ip);

  res.json({ message: 'Server removed' });
});

/**
 * GET /api/v1/servers/:id/health — health history
 */
router.get('/servers/:id/health', authenticate, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const snapshots = db.prepare(
    'SELECT * FROM health_snapshots WHERE server_id = ? ORDER BY recorded_at DESC LIMIT ?'
  ).all(req.params.id, limit);

  res.json(snapshots);
});

// ─── Install Tokens ─────────────────────────────────────────

/**
 * POST /api/v1/tokens — generate an install token
 */
router.post('/tokens', authenticate, requireRole('admin'), (req, res) => {
  const { server_name, expires_hours } = req.body;
  const hours = parseInt(expires_hours) || 24;

  const id = crypto.randomUUID();
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO install_tokens (id, token, server_name, created_by, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, token, server_name || null, req.user.id, expiresAt);

  audit(req.user.id, 'token_created', `Install token created for: ${server_name || 'unnamed'}`, req.ip);

  res.status(201).json({ id, token, server_name, expires_at: expiresAt });
});

/**
 * GET /api/v1/tokens — list active tokens
 */
router.get('/tokens', authenticate, requireRole('admin'), (req, res) => {
  const tokens = db.prepare(`
    SELECT t.*, u.username AS created_by_username
    FROM install_tokens t
    LEFT JOIN users u ON u.id = t.created_by
    WHERE t.active = 1
    ORDER BY t.created_at DESC
  `).all();

  res.json(tokens);
});

/**
 * DELETE /api/v1/tokens/:id — revoke a token
 */
router.delete('/tokens/:id', authenticate, requireRole('admin'), (req, res) => {
  const token = db.prepare('SELECT id FROM install_tokens WHERE id = ?').get(req.params.id);
  if (!token) {
    return res.status(404).json({ error: 'Token not found' });
  }

  db.prepare('UPDATE install_tokens SET active = 0 WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'token_revoked', 'Install token revoked', req.ip);

  res.json({ message: 'Token revoked' });
});

/**
 * POST /api/v1/servers/register — called by installer with token
 * No auth required — uses install token instead
 */
router.post('/servers/register', (req, res) => {
  const { token, name, hostname, ip_address, gateway_url, agent_name } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Install token required' });
  }

  const installToken = db.prepare(`
    SELECT * FROM install_tokens
    WHERE token = ? AND active = 1 AND used_at IS NULL
  `).get(token);

  if (!installToken) {
    return res.status(401).json({ error: 'Invalid or used token' });
  }

  // Check expiry
  if (new Date(installToken.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Token expired' });
  }

  // Register the server
  const serverId = crypto.randomUUID();
  const serverName = name || installToken.server_name || hostname || 'Unnamed Server';

  db.prepare(`
    INSERT INTO servers (id, name, hostname, ip_address, gateway_url, agent_name, status, registered_by)
    VALUES (?, ?, ?, ?, ?, ?, 'online', ?)
  `).run(serverId, serverName, hostname || null, ip_address || null,
    gateway_url || null, agent_name || null, installToken.created_by);

  // Mark token as used
  db.prepare(
    "UPDATE install_tokens SET used_at = datetime('now'), used_by_server = ? WHERE id = ?"
  ).run(serverId, installToken.id);

  audit(installToken.created_by, 'server_registered',
    `Server registered via token: ${serverName}`, req.ip, serverId);

  res.status(201).json({ id: serverId, name: serverName, message: 'Server registered successfully' });
});

// ─── Audit Log ──────────────────────────────────────────────

/**
 * GET /api/v1/audit — audit log
 */
router.get('/audit', authenticate, requireRole('admin'), (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const logs = db.prepare(`
    SELECT a.*, u.username, s.name AS server_name
    FROM audit_log a
    LEFT JOIN users u ON u.id = a.user_id
    LEFT JOIN servers s ON s.id = a.server_id
    ORDER BY a.created_at DESC
    LIMIT ?
  `).all(limit);

  res.json(logs);
});

export default router;
