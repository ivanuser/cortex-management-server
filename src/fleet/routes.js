import { Router } from 'express';
import crypto from 'crypto';
import { db } from '../db/init.js';
import { authenticate, requireRole } from '../auth/middleware.js';
import { getActiveIncidentCount } from './incident-response.js';
import { fireWebhookEvent, sendTestWebhook, WEBHOOK_EVENTS } from './webhooks.js';
import { calculateNextRun } from './scheduler.js';
import { getTemplates, getTemplate, applyTemplate } from './templates.js';

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

  // Attach active incident count per server
  for (const s of servers) {
    s.active_incidents = getActiveIncidentCount(s.id);
  }

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

  // Clean up all associated data
  const healthDeleted = db.prepare('DELETE FROM health_snapshots WHERE server_id = ?').run(req.params.id);
  const backupsDeleted = db.prepare('DELETE FROM agent_backups WHERE server_id = ?').run(req.params.id);
  // Clear foreign key reference in install_tokens
  db.prepare('UPDATE install_tokens SET used_by_server = NULL WHERE used_by_server = ?').run(req.params.id);
  // Clear any audit log references
  db.prepare('UPDATE audit_log SET server_id = NULL WHERE server_id = ?').run(req.params.id);
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
  const { server_name, expires_hours, provider, api_key, template_id } = req.body;
  const hours = parseInt(expires_hours) || 24;

  const id = crypto.randomUUID();
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

  // Store provider, API key, and template with the token
  const config = JSON.stringify({ provider: provider || 'skip', api_key: api_key || '', template_id: template_id || '' });

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

  // Apply template if one was specified in the token config
  try {
    const tokenConfig = JSON.parse(installToken.config || '{}');
    if (tokenConfig.template_id) {
      const registeredServer = db.prepare('SELECT * FROM servers WHERE id = ?').get(serverId);
      if (registeredServer) {
        // Delay template application to give the server time to boot
        setTimeout(() => {
          applyTemplate(registeredServer, tokenConfig.template_id);
        }, 30_000);
      }
    }
  } catch {}

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

// ─── Incidents ──────────────────────────────────────────────

/**
 * GET /api/v1/incidents — list recent incidents
 */
router.get('/incidents', authenticate, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const serverId = req.query.server_id || null;
  const resolved = req.query.resolved;

  let where = [];
  let params = [];

  if (serverId) {
    where.push('i.server_id = ?');
    params.push(serverId);
  }
  if (resolved !== undefined) {
    where.push('i.resolved = ?');
    params.push(resolved === 'true' || resolved === '1' ? 1 : 0);
  }

  const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';
  params.push(limit);

  const incidents = db.prepare(`
    SELECT i.*, s.name as server_name
    FROM incidents i
    JOIN servers s ON s.id = i.server_id
    ${whereClause}
    ORDER BY i.created_at DESC
    LIMIT ?
  `).all(...params);

  res.json(incidents);
});

/**
 * PUT /api/v1/incidents/:id/resolve — manually resolve an incident
 */
router.put('/incidents/:id/resolve', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const incident = db.prepare('SELECT id FROM incidents WHERE id = ?').get(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });

  db.prepare(
    "UPDATE incidents SET resolved = 1, resolved_at = datetime('now') WHERE id = ?"
  ).run(req.params.id);

  audit(req.user.id, 'incident_resolved', 'Manually resolved incident', req.ip);
  res.json({ message: 'Incident resolved' });
});

// ─── Scheduled Operations ───────────────────────────────────

/**
 * POST /api/v1/schedules — create a scheduled operation
 */
router.post('/schedules', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const { name, server_ids, command, cron_expr, enabled } = req.body;

  if (!name || !command || !cron_expr) {
    return res.status(400).json({ error: 'Name, command, and cron expression required' });
  }

  const id = crypto.randomUUID();
  const serverIdsStr = !server_ids || server_ids === '*' ? '*' : JSON.stringify(server_ids);
  const nextRun = calculateNextRun(cron_expr);

  db.prepare(`
    INSERT INTO scheduled_ops (id, name, server_ids, command, cron_expr, enabled, created_by, next_run)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, serverIdsStr, command, cron_expr, enabled !== false ? 1 : 0, req.user.id, nextRun);

  audit(req.user.id, 'schedule_created', `Created schedule: ${name}`, req.ip);
  res.status(201).json({ id, name, next_run: nextRun });
});

/**
 * GET /api/v1/schedules — list all scheduled operations
 */
router.get('/schedules', authenticate, (req, res) => {
  const schedules = db.prepare(`
    SELECT s.*, u.username as created_by_username
    FROM scheduled_ops s
    LEFT JOIN users u ON u.id = s.created_by
    ORDER BY s.created_at DESC
  `).all();
  res.json(schedules);
});

/**
 * PUT /api/v1/schedules/:id — update a scheduled operation
 */
router.put('/schedules/:id', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const sched = db.prepare('SELECT * FROM scheduled_ops WHERE id = ?').get(req.params.id);
  if (!sched) return res.status(404).json({ error: 'Schedule not found' });

  const { name, server_ids, command, cron_expr, enabled } = req.body;
  const newName = name || sched.name;
  const newCommand = command || sched.command;
  const newCron = cron_expr || sched.cron_expr;
  const newEnabled = enabled !== undefined ? (enabled ? 1 : 0) : sched.enabled;
  const newServerIds = server_ids !== undefined
    ? (server_ids === '*' ? '*' : JSON.stringify(server_ids))
    : sched.server_ids;
  const nextRun = calculateNextRun(newCron);

  db.prepare(`
    UPDATE scheduled_ops SET name = ?, server_ids = ?, command = ?, cron_expr = ?, enabled = ?, next_run = ?
    WHERE id = ?
  `).run(newName, newServerIds, newCommand, newCron, newEnabled, nextRun, req.params.id);

  audit(req.user.id, 'schedule_updated', `Updated schedule: ${newName}`, req.ip);
  res.json({ message: 'Schedule updated' });
});

/**
 * DELETE /api/v1/schedules/:id — delete a scheduled operation
 */
router.delete('/schedules/:id', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const sched = db.prepare('SELECT name FROM scheduled_ops WHERE id = ?').get(req.params.id);
  if (!sched) return res.status(404).json({ error: 'Schedule not found' });

  db.prepare('DELETE FROM scheduled_ops WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'schedule_deleted', `Deleted schedule: ${sched.name}`, req.ip);
  res.json({ message: 'Schedule deleted' });
});

// ─── Webhooks ───────────────────────────────────────────────

/**
 * POST /api/v1/webhooks — create a webhook
 */
router.post('/webhooks', authenticate, requireRole('admin'), (req, res) => {
  const { name, url, events, enabled } = req.body;

  if (!name || !url) {
    return res.status(400).json({ error: 'Name and URL required' });
  }

  const id = crypto.randomUUID();
  db.prepare(
    'INSERT INTO webhooks (id, name, url, events, enabled, created_by) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, name, url, JSON.stringify(events || []), enabled !== false ? 1 : 0, req.user.id);

  audit(req.user.id, 'webhook_created', `Created webhook: ${name}`, req.ip);
  res.status(201).json({ id, name });
});

/**
 * GET /api/v1/webhooks — list webhooks
 */
router.get('/webhooks', authenticate, (req, res) => {
  const webhooks = db.prepare(`
    SELECT w.*, u.username as created_by_username
    FROM webhooks w
    LEFT JOIN users u ON u.id = w.created_by
    ORDER BY w.created_at DESC
  `).all();
  res.json(webhooks);
});

/**
 * PUT /api/v1/webhooks/:id — update a webhook
 */
router.put('/webhooks/:id', authenticate, requireRole('admin'), (req, res) => {
  const wh = db.prepare('SELECT * FROM webhooks WHERE id = ?').get(req.params.id);
  if (!wh) return res.status(404).json({ error: 'Webhook not found' });

  const { name, url, events, enabled } = req.body;
  db.prepare(`
    UPDATE webhooks SET name = ?, url = ?, events = ?, enabled = ? WHERE id = ?
  `).run(
    name || wh.name,
    url || wh.url,
    events !== undefined ? JSON.stringify(events) : wh.events,
    enabled !== undefined ? (enabled ? 1 : 0) : wh.enabled,
    req.params.id
  );

  audit(req.user.id, 'webhook_updated', `Updated webhook: ${name || wh.name}`, req.ip);
  res.json({ message: 'Webhook updated' });
});

/**
 * DELETE /api/v1/webhooks/:id — delete a webhook
 */
router.delete('/webhooks/:id', authenticate, requireRole('admin'), (req, res) => {
  const wh = db.prepare('SELECT name FROM webhooks WHERE id = ?').get(req.params.id);
  if (!wh) return res.status(404).json({ error: 'Webhook not found' });

  db.prepare('DELETE FROM webhooks WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'webhook_deleted', `Deleted webhook: ${wh.name}`, req.ip);
  res.json({ message: 'Webhook deleted' });
});

/**
 * POST /api/v1/webhooks/:id/test — send a test notification
 */
router.post('/webhooks/:id/test', authenticate, requireRole('admin'), async (req, res) => {
  const wh = db.prepare('SELECT * FROM webhooks WHERE id = ?').get(req.params.id);
  if (!wh) return res.status(404).json({ error: 'Webhook not found' });

  try {
    await sendTestWebhook(wh);
    res.json({ message: 'Test notification sent' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to send test: ' + e.message });
  }
});

/**
 * GET /api/v1/webhooks/events — list available webhook events
 */
router.get('/webhooks/events', authenticate, (_req, res) => {
  res.json(WEBHOOK_EVENTS);
});

// ─── Templates ──────────────────────────────────────────────

/**
 * GET /api/v1/templates — list all server templates
 */
router.get('/templates', authenticate, (_req, res) => {
  res.json(getTemplates());
});

/**
 * GET /api/v1/templates/:id — get a specific template
 */
router.get('/templates/:id', authenticate, (req, res) => {
  const template = getTemplate(req.params.id);
  if (!template) return res.status(404).json({ error: 'Template not found' });
  res.json(template);
});

// ─── Fleet Command ──────────────────────────────────────────

/**
 * POST /api/v1/fleet/command — send a command to multiple servers
 */
router.post('/fleet/command', authenticate, requireRole('admin', 'operator'), async (req, res) => {
  const { command, server_ids } = req.body;

  if (!command) return res.status(400).json({ error: 'Command required' });

  let targetServers;
  if (!server_ids || server_ids === '*') {
    targetServers = db.prepare(
      'SELECT id, name, gateway_url, gateway_token, status FROM servers'
    ).all();
  } else {
    const ids = Array.isArray(server_ids) ? server_ids : [server_ids];
    const placeholders = ids.map(() => '?').join(',');
    targetServers = db.prepare(
      `SELECT id, name, gateway_url, gateway_token, status FROM servers WHERE id IN (${placeholders})`
    ).all(...ids);
  }

  const results = [];
  for (const server of targetServers) {
    if (server.status === 'offline' || !server.gateway_url || !server.gateway_token) {
      results.push({ server_id: server.id, server_name: server.name, status: 'skipped', reason: 'offline or no gateway' });
      continue;
    }
    results.push({ server_id: server.id, server_name: server.name, status: 'sent' });
    // Fire command asynchronously
    sendFleetCommand(server, command);
  }

  audit(req.user.id, 'fleet_command', `Fleet command sent to ${results.filter(r => r.status === 'sent').length} servers: ${command.slice(0, 100)}`, req.ip);
  res.json({ results, command });
});

/**
 * Send a fleet command to a single server via WebSocket
 */
async function sendFleetCommand(server, command) {
  try {
    const { WebSocket } = await import('ws');
    const gwUrl = server.gateway_url.replace(/^http/, 'ws').replace(/\/$/, '');

    const ws = new WebSocket(gwUrl);
    const timeout = setTimeout(() => ws.close(), 15_000);

    ws.on('open', () => {
      ws.send(JSON.stringify({
        type: 'req', id: 'connect', method: 'connect',
        params: {
          minProtocol: 3, maxProtocol: 3,
          client: { id: 'fleet-cmd', displayName: 'Fleet Command', version: '1.0.0', platform: 'server', mode: 'webchat' },
          scopes: ['operator.admin'],
          auth: { token: server.gateway_token }
        }
      }));
    });

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'res' && msg.id === 'connect' && msg.ok) {
          ws.send(JSON.stringify({
            type: 'req', method: 'chat.send', id: 'fleet-' + crypto.randomUUID(),
            params: {
              sessionKey: 'agent:main:webchat',
              message: command,
              idempotencyKey: crypto.randomUUID()
            }
          }));
          setTimeout(() => ws.close(), 5000);
        }
        if (msg.type === 'event' && msg.event === 'connect.challenge') {
          ws.send(JSON.stringify({
            type: 'req', id: 'connect', method: 'connect',
            params: {
              minProtocol: 3, maxProtocol: 3,
              client: { id: 'fleet-cmd', displayName: 'Fleet Command', version: '1.0.0', platform: 'server', mode: 'webchat' },
              scopes: ['operator.admin'],
              auth: { token: server.gateway_token }
            }
          }));
        }
      } catch {}
    });

    ws.on('error', () => {});
    ws.on('close', () => clearTimeout(timeout));
  } catch (err) {
    console.error(`[Fleet] Failed to send to ${server.name}:`, err.message);
  }
}

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
