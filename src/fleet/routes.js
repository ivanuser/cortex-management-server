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
 * DELETE /api/v1/servers/:id — remove a server and all associated data
 */
router.delete('/servers/:id', authenticate, requireRole('admin'), (req, res) => {
  const server = db.prepare('SELECT name FROM servers WHERE id = ?').get(req.params.id);
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  // Explicitly clean up associated data (also handled by ON DELETE CASCADE)
  const healthDeleted = db.prepare('DELETE FROM health_snapshots WHERE server_id = ?').run(req.params.id);
  const backupsDeleted = db.prepare('DELETE FROM agent_backups WHERE server_id = ?').run(req.params.id);
  db.prepare('DELETE FROM servers WHERE id = ?').run(req.params.id);

  audit(req.user.id, 'server_removed',
    `Removed server: ${server.name} (${healthDeleted.changes} health snapshots, ${backupsDeleted.changes} backups cleaned up)`,
    req.ip);

  res.json({ message: 'Server removed', cleaned: { health_snapshots: healthDeleted.changes, backups: backupsDeleted.changes } });
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
  const { server_name, expires_hours, provider, api_key } = req.body;
  const hours = parseInt(expires_hours) || 24;

  const id = crypto.randomUUID();
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

  // Store provider and API key with the token (they'll be injected into the install script)
  const config = JSON.stringify({ provider: provider || 'skip', api_key: api_key || '' });

  db.prepare(`
    INSERT INTO install_tokens (id, token, server_name, created_by, expires_at, config)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, token, server_name || null, req.user.id, expiresAt, config);

  audit(req.user.id, 'token_created', `Install token created for: ${server_name || 'unnamed'} (${provider || 'no provider'})`, req.ip);

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
  const { token, name, hostname, ip_address, gateway_url, gateway_token, agent_name } = req.body;

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
    INSERT INTO servers (id, name, hostname, ip_address, gateway_url, gateway_token, agent_name, status, registered_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?)
  `).run(serverId, serverName, hostname || null, ip_address || null,
    gateway_url || null, gateway_token || null, agent_name || null, installToken.created_by);

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
 * GET /api/v1/audit — audit log with filtering and pagination
 */
router.get('/audit', authenticate, requireRole('admin'), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 500);
  const offset = parseInt(req.query.offset) || 0;
  const action = req.query.action || null;

  let where = '';
  const params = [];

  if (action) {
    where = 'WHERE a.action = ?';
    params.push(action);
  }

  params.push(limit, offset);

  const logs = db.prepare(`
    SELECT a.*, u.username, s.name AS server_name
    FROM audit_log a
    LEFT JOIN users u ON u.id = a.user_id
    LEFT JOIN servers s ON s.id = a.server_id
    ${where}
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params);

  // Get total count for pagination
  const countParams = action ? [action] : [];
  const total = db.prepare(`
    SELECT COUNT(*) as count FROM audit_log a ${where}
  `).get(...countParams);

  // Get distinct action types for filtering
  const actions = db.prepare(
    'SELECT DISTINCT action FROM audit_log ORDER BY action'
  ).all().map(r => r.action);

  res.json({ logs, total: total.count, limit, offset, actions });
});

// ─── Centralized Backups ────────────────────────────────────

// Ensure agent_backups table exists
db.exec(`
  CREATE TABLE IF NOT EXISTS agent_backups (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    created_by TEXT,
    file_count INTEGER DEFAULT 0,
    total_size INTEGER DEFAULT 0,
    files_json TEXT DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_backups_server_id ON agent_backups(server_id);
`);

/**
 * POST /api/v1/servers/:id/backup — trigger backup of server agent state
 */
router.post('/servers/:id/backup', authenticate, requireRole('admin', 'operator'), async (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  if (!server.gateway_url || !server.gateway_token) {
    return res.status(400).json({ error: 'Server has no gateway configured' });
  }

  const backupId = crypto.randomUUID();
  db.prepare(
    'INSERT INTO agent_backups (id, server_id, created_by, status) VALUES (?, ?, ?, ?)'
  ).run(backupId, server.id, req.user.id, 'in_progress');

  audit(req.user.id, 'backup_started', `Backup started for server: ${server.name}`, req.ip, server.id);

  // Start async backup
  performBackup(backupId, server, req.user.id, req.ip).catch(err => {
    console.error(`Backup ${backupId} failed:`, err.message);
  });

  res.status(202).json({ id: backupId, status: 'in_progress', message: 'Backup started' });
});

/**
 * Perform the actual backup — fetch workspace files from server gateway
 */
async function performBackup(backupId, server, userId, ip) {
  const baseUrl = server.gateway_url.replace(/\/+$/, '');
  const headers = {
    'Authorization': `Bearer ${server.gateway_token}`,
    'Content-Type': 'application/json'
  };

  try {
    // Try to list workspace files via the gateway API
    const listRes = await fetch(`${baseUrl}/api/agents/main/files`, {
      headers,
      signal: AbortSignal.timeout(30000)
    });

    let files = [];
    let totalSize = 0;

    if (listRes.ok) {
      const fileList = await listRes.json();
      const fileEntries = Array.isArray(fileList) ? fileList : (fileList.files || []);

      // Fetch each file's content
      for (const f of fileEntries) {
        try {
          const filePath = typeof f === 'string' ? f : (f.path || f.name);
          if (!filePath) continue;

          const fileRes = await fetch(`${baseUrl}/api/agents/main/files/${encodeURIComponent(filePath)}`, {
            headers,
            signal: AbortSignal.timeout(15000)
          });

          if (fileRes.ok) {
            const content = await fileRes.text();
            files.push({
              path: filePath,
              size: content.length,
              content: content
            });
            totalSize += content.length;
          }
        } catch (fileErr) {
          // Skip individual file errors
          console.error(`Backup file fetch error:`, fileErr.message);
        }
      }
    } else {
      // Fallback: try fetching known workspace files directly
      const knownFiles = ['SOUL.md', 'AGENTS.md', 'USER.md', 'TOOLS.md', 'IDENTITY.md', 'HEARTBEAT.md', 'MEMORY.md'];
      for (const fname of knownFiles) {
        try {
          const fileRes = await fetch(`${baseUrl}/api/agents/main/files/${encodeURIComponent(fname)}`, {
            headers,
            signal: AbortSignal.timeout(10000)
          });
          if (fileRes.ok) {
            const content = await fileRes.text();
            files.push({ path: fname, size: content.length, content });
            totalSize += content.length;
          }
        } catch {}
      }
    }

    // Update backup record
    db.prepare(`
      UPDATE agent_backups 
      SET status = 'completed', file_count = ?, total_size = ?, files_json = ?, completed_at = datetime('now')
      WHERE id = ?
    `).run(files.length, totalSize, JSON.stringify(files), backupId);

    audit(userId, 'backup_completed', `Backup completed for server: ${server.name} (${files.length} files, ${totalSize} bytes)`, ip, server.id);

  } catch (err) {
    db.prepare(`
      UPDATE agent_backups SET status = 'failed', error = ?, completed_at = datetime('now') WHERE id = ?
    `).run(err.message, backupId);

    audit(userId, 'backup_failed', `Backup failed for server: ${server.name} — ${err.message}`, ip, server.id);
  }
}

/**
 * GET /api/v1/servers/:id/backups — list backups for a server
 */
router.get('/servers/:id/backups', authenticate, (req, res) => {
  const server = db.prepare('SELECT id FROM servers WHERE id = ?').get(req.params.id);
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  const backups = db.prepare(`
    SELECT b.id, b.server_id, b.file_count, b.total_size, b.status, b.error, b.created_at, b.completed_at,
           u.username AS created_by_username
    FROM agent_backups b
    LEFT JOIN users u ON u.id = b.created_by
    WHERE b.server_id = ?
    ORDER BY b.created_at DESC
    LIMIT 50
  `).all(req.params.id);

  res.json(backups);
});

/**
 * GET /api/v1/backups/:id — download a specific backup
 */
router.get('/backups/:id', authenticate, (req, res) => {
  const backup = db.prepare(
    'SELECT * FROM agent_backups WHERE id = ?'
  ).get(req.params.id);

  if (!backup) {
    return res.status(404).json({ error: 'Backup not found' });
  }

  if (backup.status !== 'completed') {
    return res.status(400).json({ error: `Backup is ${backup.status}`, status: backup.status });
  }

  // Return as JSON with file contents
  const files = JSON.parse(backup.files_json || '[]');
  res.json({
    id: backup.id,
    server_id: backup.server_id,
    file_count: backup.file_count,
    total_size: backup.total_size,
    created_at: backup.created_at,
    completed_at: backup.completed_at,
    files: files.map(f => ({ path: f.path, size: f.size, content: f.content }))
  });
});

/**
 * DELETE /api/v1/backups/:id — delete a backup
 */
router.delete('/backups/:id', authenticate, requireRole('admin'), (req, res) => {
  const backup = db.prepare('SELECT id FROM agent_backups WHERE id = ?').get(req.params.id);
  if (!backup) {
    return res.status(404).json({ error: 'Backup not found' });
  }

  db.prepare('DELETE FROM agent_backups WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'backup_deleted', 'Backup deleted', req.ip);
  res.json({ message: 'Backup deleted' });
});

export default router;
