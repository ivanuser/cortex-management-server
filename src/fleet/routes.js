import { Router } from 'express';
import crypto from 'crypto';
import { db } from '../db/init.js';
import { authenticate, requireRole } from '../auth/middleware.js';
import { getActiveIncidentCount } from './incident-response.js';
import { fireWebhookEvent, sendTestWebhook, WEBHOOK_EVENTS } from './webhooks.js';
import { calculateNextRun } from './scheduler.js';
import { getTemplates, getTemplate, applyTemplate } from './templates.js';
import { getLatestVersion } from './health-poller.js';

const router = Router();

// Helper to log audit events
function audit(userId, action, details, ip, serverId = null) {
  db.prepare(
    'INSERT INTO audit_log (id, user_id, server_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), userId, serverId, action, details, ip);
}

// ─── Server Groups ──────────────────────────────────────────

/**
 * GET /api/v1/groups — list all groups with member counts and aggregate health
 */
router.get('/groups', authenticate, (req, res) => {
  const groups = db.prepare(`
    SELECT g.*,
      COUNT(gm.server_id) AS member_count,
      u.username AS created_by_username
    FROM server_groups g
    LEFT JOIN server_group_members gm ON gm.group_id = g.id
    LEFT JOIN users u ON u.id = g.created_by
    GROUP BY g.id
    ORDER BY g.name
  `).all();

  // Attach aggregate health per group
  for (const g of groups) {
    const stats = db.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN s.status = 'online' THEN 1 ELSE 0 END) AS online,
        SUM(CASE WHEN s.status = 'offline' THEN 1 ELSE 0 END) AS offline,
        AVG(h.cpu_percent) AS avg_cpu,
        AVG(CASE WHEN h.memory_total_mb > 0 THEN h.memory_used_mb * 100.0 / h.memory_total_mb ELSE NULL END) AS avg_memory_pct
      FROM server_group_members gm
      JOIN servers s ON s.id = gm.server_id
      LEFT JOIN health_snapshots h ON h.id = (
        SELECT h2.id FROM health_snapshots h2
        WHERE h2.server_id = s.id
        ORDER BY h2.recorded_at DESC LIMIT 1
      )
      WHERE gm.group_id = ?
    `).get(g.id);
    g.stats = {
      total: stats?.total || 0,
      online: stats?.online || 0,
      offline: stats?.offline || 0,
      avg_cpu: stats?.avg_cpu ? parseFloat(stats.avg_cpu.toFixed(1)) : null,
      avg_memory_pct: stats?.avg_memory_pct ? parseFloat(stats.avg_memory_pct.toFixed(1)) : null
    };
  }

  res.json(groups);
});

/**
 * GET /api/v1/groups/:id — group detail with servers and aggregate stats
 */
router.get('/groups/:id', authenticate, (req, res) => {
  const group = db.prepare(`
    SELECT g.*, u.username AS created_by_username
    FROM server_groups g
    LEFT JOIN users u ON u.id = g.created_by
    WHERE g.id = ?
  `).get(req.params.id);

  if (!group) return res.status(404).json({ error: 'Group not found' });

  const servers = db.prepare(`
    SELECT s.*,
      h.cpu_percent, h.memory_used_mb, h.memory_total_mb,
      h.disk_used_gb, h.disk_total_gb, h.disk_percent, h.uptime,
      h.recorded_at AS health_recorded_at
    FROM server_group_members gm
    JOIN servers s ON s.id = gm.server_id
    LEFT JOIN health_snapshots h ON h.id = (
      SELECT h2.id FROM health_snapshots h2
      WHERE h2.server_id = s.id
      ORDER BY h2.recorded_at DESC LIMIT 1
    )
    WHERE gm.group_id = ?
    ORDER BY s.name
  `).all(req.params.id);

  const online = servers.filter(s => s.status === 'online').length;
  const offline = servers.filter(s => s.status === 'offline').length;
  const avgCpu = servers.reduce((sum, s) => sum + (s.cpu_percent || 0), 0) / (servers.length || 1);
  const avgMem = servers.reduce((sum, s) => {
    if (s.memory_used_mb && s.memory_total_mb) return sum + (s.memory_used_mb / s.memory_total_mb * 100);
    return sum;
  }, 0) / (servers.length || 1);

  group.servers = servers;
  group.stats = {
    total: servers.length,
    online, offline,
    avg_cpu: parseFloat(avgCpu.toFixed(1)),
    avg_memory_pct: parseFloat(avgMem.toFixed(1))
  };

  res.json(group);
});

/**
 * POST /api/v1/groups — create a group
 */
router.post('/groups', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const { name, description, icon, color } = req.body;
  if (!name) return res.status(400).json({ error: 'Group name required' });

  const id = crypto.randomUUID();
  db.prepare(`
    INSERT INTO server_groups (id, name, description, icon, color, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, name, description || null, icon || '📁', color || '#6366f1', req.user.id);

  audit(req.user.id, 'group_created', `Created group: ${name}`, req.ip);
  res.status(201).json({ id, name });
});

/**
 * PUT /api/v1/groups/:id — update a group
 */
router.put('/groups/:id', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const group = db.prepare('SELECT * FROM server_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  const { name, description, icon, color } = req.body;
  db.prepare(`
    UPDATE server_groups SET name = ?, description = ?, icon = ?, color = ?
    WHERE id = ?
  `).run(
    name || group.name,
    description !== undefined ? description : group.description,
    icon || group.icon,
    color || group.color,
    req.params.id
  );

  audit(req.user.id, 'group_updated', `Updated group: ${name || group.name}`, req.ip);
  res.json({ message: 'Group updated' });
});

/**
 * DELETE /api/v1/groups/:id — delete a group
 */
router.delete('/groups/:id', authenticate, requireRole('admin'), (req, res) => {
  const group = db.prepare('SELECT name FROM server_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  db.prepare('DELETE FROM server_groups WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'group_deleted', `Deleted group: ${group.name}`, req.ip);
  res.json({ message: 'Group deleted' });
});

/**
 * POST /api/v1/groups/:id/servers — add a server to a group
 */
router.post('/groups/:id/servers', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const { server_id } = req.body;
  if (!server_id) return res.status(400).json({ error: 'server_id required' });

  const group = db.prepare('SELECT name FROM server_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  const server = db.prepare('SELECT name FROM servers WHERE id = ?').get(server_id);
  if (!server) return res.status(404).json({ error: 'Server not found' });

  try {
    db.prepare('INSERT OR IGNORE INTO server_group_members (group_id, server_id) VALUES (?, ?)').run(req.params.id, server_id);
  } catch (e) {
    return res.status(409).json({ error: 'Server already in group' });
  }

  audit(req.user.id, 'group_server_added', `Added ${server.name} to group ${group.name}`, req.ip);
  res.status(201).json({ message: 'Server added to group' });
});

/**
 * DELETE /api/v1/groups/:id/servers/:serverId — remove a server from a group
 */
router.delete('/groups/:id/servers/:serverId', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const result = db.prepare('DELETE FROM server_group_members WHERE group_id = ? AND server_id = ?').run(req.params.id, req.params.serverId);
  if (result.changes === 0) return res.status(404).json({ error: 'Membership not found' });
  res.json({ message: 'Server removed from group' });
});

/**
 * GET /api/v1/servers/:id/groups — get groups for a specific server
 */
router.get('/servers/:id/groups', authenticate, (req, res) => {
  const groups = db.prepare(`
    SELECT g.id, g.name, g.icon, g.color
    FROM server_group_members gm
    JOIN server_groups g ON g.id = gm.group_id
    WHERE gm.server_id = ?
    ORDER BY g.name
  `).all(req.params.id);
  res.json(groups);
});

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
 * PUT /api/v1/servers/:id — update server details
 */
router.put('/servers/:id', authenticate, requireRole('admin', 'operator'), (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  const { name, agent_name, hostname, ip_address, gateway_url, gateway_token, tags, avatar_data } = req.body;

  const newName = name !== undefined ? name : server.name;
  const newAgentName = agent_name !== undefined ? agent_name : server.agent_name;
  const newHostname = hostname !== undefined ? hostname : server.hostname;
  const newIpAddress = ip_address !== undefined ? ip_address : server.ip_address;
  const newGatewayUrl = gateway_url !== undefined ? gateway_url : server.gateway_url;
  const newGatewayToken = gateway_token !== undefined ? gateway_token : server.gateway_token;
  const newTags = tags !== undefined ? JSON.stringify(tags) : server.tags;
  const newAvatarData = avatar_data !== undefined ? avatar_data : server.avatar_data;

  if (!newName) {
    return res.status(400).json({ error: 'Server name cannot be empty' });
  }

  db.prepare(`
    UPDATE servers SET name = ?, agent_name = ?, hostname = ?, ip_address = ?,
      gateway_url = ?, gateway_token = ?, tags = ?, avatar_data = ?
    WHERE id = ?
  `).run(newName, newAgentName, newHostname, newIpAddress,
    newGatewayUrl, newGatewayToken, newTags, newAvatarData, req.params.id);

  audit(req.user.id, 'server_updated', `Updated server: ${newName}`, req.ip, req.params.id);
  res.json({ message: 'Server updated', id: req.params.id });
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
 * GET /api/v1/servers/:id/proxy/:file — proxy file requests to server gateway
 * Solves mixed content (HTTPS dashboard → HTTP server)
 */
router.get('/servers/:id/proxy/:file', authenticate, async (req, res) => {
  const server = db.prepare('SELECT gateway_url FROM servers WHERE id = ?').get(req.params.id);
  if (!server || !server.gateway_url) {
    return res.status(404).json({ error: 'Server not found' });
  }
  const url = server.gateway_url.replace(/\/+$/, '') + '/' + req.params.file;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);
    if (!response.ok) return res.status(response.status).json({ error: 'Upstream error' });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: 'Failed to reach server: ' + err.message });
  }
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

    console.log(`[Fleet] Sending command to ${server.name} (${gwUrl}): ${command.substring(0, 60)}...`);
    const ws = new WebSocket(gwUrl, {
      headers: { 'Origin': server.gateway_url }
    });
    const timeout = setTimeout(() => { console.log(`[Fleet] Timeout for ${server.name}`); ws.close(); }, 15_000);

    ws.on('open', () => {
      console.log(`[Fleet] Connected to ${server.name}`);
      ws.send(JSON.stringify({
        type: 'req', id: 'connect', method: 'connect',
        params: {
          minProtocol: 3, maxProtocol: 3,
          client: { id: 'webchat-ui', displayName: 'Fleet Command', version: '1.0.0', platform: 'server', mode: 'webchat' },
          scopes: ['operator.admin'],
          auth: { token: server.gateway_token }
        }
      }));
    });

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'res' && msg.id === 'connect' && msg.ok) {
          console.log(`[Fleet] Auth OK for ${server.name}, sending command...`);
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
              client: { id: 'webchat-ui', displayName: 'Fleet Command', version: '1.0.0', platform: 'server', mode: 'webchat' },
              scopes: ['operator.admin'],
              auth: { token: server.gateway_token }
            }
          }));
        }
      } catch {}
    });

    ws.on('error', (err) => { console.error(`[Fleet] WS error for ${server.name}:`, err.message); });
    ws.on('close', () => clearTimeout(timeout));
  } catch (err) {
    console.error(`[Fleet] Failed to send to ${server.name}:`, err.message);
  }
}

// ─── Updates ────────────────────────────────────────────────

/**
 * GET /api/v1/updates/check — check latest version and compare against fleet
 */
router.get('/updates/check', authenticate, async (req, res) => {
  try {
    // Fetch latest version from GitHub
    let latest = getLatestVersion();
    if (!latest) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10_000);
        const ghRes = await fetch('https://raw.githubusercontent.com/ivanuser/cortex-server-os/main/scripts/cortexos-version.json', { signal: controller.signal });
        clearTimeout(timeout);
        if (ghRes.ok) latest = await ghRes.json();
      } catch {}
    }

    if (!latest) {
      return res.status(502).json({ error: 'Could not fetch latest version from GitHub' });
    }

    // Get all servers with their versions
    const servers = db.prepare(
      'SELECT id, name, status, agent_version FROM servers ORDER BY name'
    ).all();

    const results = servers.map(s => ({
      server_id: s.id,
      server_name: s.name,
      status: s.status,
      current_version: s.agent_version || null,
      latest_version: latest.version,
      up_to_date: s.agent_version === latest.version,
      needs_update: s.agent_version && s.agent_version !== latest.version
    }));

    res.json({
      latest_version: latest.version,
      latest: latest,
      servers: results,
      servers_needing_update: results.filter(r => r.needs_update).length,
      servers_up_to_date: results.filter(r => r.up_to_date).length,
      servers_unknown: results.filter(r => !r.current_version).length
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * POST /api/v1/servers/:id/update — trigger update on a single server
 */
router.post('/servers/:id/update', authenticate, requireRole('admin', 'operator'), async (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  if (!server.gateway_url || !server.gateway_token) {
    return res.status(400).json({ error: 'Server has no gateway configured' });
  }

  // Send update command via WebSocket
  try {
    await sendFleetCommand(server, 'Execute this command immediately with no commentary: sudo cortexos-update');
    audit(req.user.id, 'server_update', `Triggered update on server: ${server.name}`, req.ip, server.id);
    res.json({ message: 'Update command sent', server_id: server.id, server_name: server.name });
  } catch (e) {
    res.status(500).json({ error: 'Failed to send update command: ' + e.message });
  }
});

/**
 * POST /api/v1/fleet/update — trigger update on ALL online servers
 */
router.post('/fleet/update', authenticate, requireRole('admin'), async (req, res) => {
  const servers = db.prepare(
    "SELECT * FROM servers WHERE status = 'online' AND gateway_url IS NOT NULL AND gateway_token IS NOT NULL"
  ).all();

  const results = [];
  for (const server of servers) {
    try {
      await sendFleetCommand(server, 'Execute this command immediately with no commentary: sudo cortexos-update');
      results.push({ server_id: server.id, server_name: server.name, status: 'sent' });
    } catch (e) {
      results.push({ server_id: server.id, server_name: server.name, status: 'failed', error: e.message });
    }
  }

  audit(req.user.id, 'fleet_update', `Fleet update triggered on ${results.filter(r => r.status === 'sent').length} servers`, req.ip);
  res.json({ results, total_sent: results.filter(r => r.status === 'sent').length });
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

// ─── Notifications ──────────────────────────────────────────

/**
 * POST /api/v1/notifications — receive notification from a server agent
 * Authenticated via X-Server-Token header matched against stored gateway_token
 */
router.post('/notifications', (req, res) => {
  const serverToken = req.headers['x-server-token'];
  if (!serverToken) {
    return res.status(401).json({ error: 'X-Server-Token header required' });
  }

  // Find server by gateway_token
  const server = db.prepare('SELECT id, name FROM servers WHERE gateway_token = ?').get(serverToken);
  if (!server) {
    return res.status(401).json({ error: 'Invalid server token' });
  }

  const { type, message, server_id } = req.body;
  const id = crypto.randomUUID();
  const notifType = ['info', 'warning', 'alert', 'critical'].includes(type) ? type : 'info';

  // Use the server_id from the token match (more reliable than body)
  db.prepare(
    'INSERT INTO notifications (id, server_id, type, message) VALUES (?, ?, ?, ?)'
  ).run(id, server.id, notifType, message || 'No message');

  res.status(201).json({ id, server_id: server.id, type: notifType, message });
});

/**
 * POST /api/v1/notifications/internal — create a notification from the dashboard UI
 */
router.post('/notifications/internal', authenticate, (req, res) => {
  const { message, type = 'info', server_id = null } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });
  const id = crypto.randomUUID();
  const notifType = ['info', 'warning', 'alert', 'critical'].includes(type) ? type : 'info';
  db.prepare('INSERT INTO notifications (id, server_id, type, message, read, created_at) VALUES (?,?,?,?,0,?)')
    .run(id, server_id, notifType, message, new Date().toISOString());
  res.json({ id, message: 'Notification created' });
});

 * GET /api/v1/notifications — list recent notifications (for dashboard)
 */
router.get('/notifications', authenticate, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const unreadOnly = req.query.unread === 'true';

  let where = '';
  if (unreadOnly) where = 'WHERE n.read = 0';

  const notifications = db.prepare(`
    SELECT n.*, s.name AS server_name
    FROM notifications n
    LEFT JOIN servers s ON s.id = n.server_id
    ${where}
    ORDER BY n.created_at DESC
    LIMIT ?
  `).all(limit);

  const unreadCount = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE read = 0').get();

  res.json({ notifications, unread_count: unreadCount.count });
});

/**
 * PUT /api/v1/notifications/:id/read — mark a single notification as read
 */
router.put('/notifications/:id/read', authenticate, (req, res) => {
  const notif = db.prepare('SELECT id FROM notifications WHERE id = ?').get(req.params.id);
  if (!notif) return res.status(404).json({ error: 'Notification not found' });

  db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').run(req.params.id);
  res.json({ message: 'Notification marked as read' });
});

/**
 * PUT /api/v1/notifications/read-all — mark all notifications as read
 */
router.put('/notifications/read-all', authenticate, (req, res) => {
  db.prepare('UPDATE notifications SET read = 1 WHERE read = 0').run();
  res.json({ message: 'All notifications marked as read' });
});

// ─── Chat History ───────────────────────────────────────────

/**
 * GET /api/v1/servers/:id/chat — get chat history for a server
 */
router.get('/servers/:id/chat', authenticate, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const messages = db.prepare(
    'SELECT id, role, content, created_at FROM chat_messages WHERE server_id = ? ORDER BY created_at DESC LIMIT ?'
  ).all(req.params.id, limit).reverse();
  res.json(messages);
});

/**
 * POST /api/v1/servers/:id/chat — save a chat message
 */
router.post('/servers/:id/chat', authenticate, (req, res) => {
  const { role, content } = req.body;
  if (!role || !content) return res.status(400).json({ error: 'role and content required' });
  
  const result = db.prepare(
    'INSERT INTO chat_messages (server_id, user_id, role, content) VALUES (?, ?, ?, ?)'
  ).run(req.params.id, req.user.id, role, content);
  
  res.status(201).json({ id: result.lastInsertRowid });
});

/**
 * DELETE /api/v1/servers/:id/chat — clear chat history for a server
 */
router.delete('/servers/:id/chat', authenticate, requireRole('admin'), (req, res) => {
  const result = db.prepare('DELETE FROM chat_messages WHERE server_id = ?').run(req.params.id);
  res.json({ deleted: result.changes });
});

// ─── Analytics ──────────────────────────────────────────────

/**
 * GET /api/v1/analytics — aggregate fleet analytics
 */
router.get('/analytics', authenticate, (req, res) => {
  // Total servers, online, offline
  const serverStats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
      SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline
    FROM servers
  `).get();

  // Average CPU/RAM/disk across fleet (from latest snapshots per server)
  const avgMetrics = db.prepare(`
    SELECT
      AVG(h.cpu_percent) as avg_cpu,
      AVG(CASE WHEN h.memory_total_mb > 0 THEN h.memory_used_mb * 100.0 / h.memory_total_mb ELSE NULL END) as avg_memory_pct,
      AVG(h.disk_percent) as avg_disk
    FROM health_snapshots h
    INNER JOIN (
      SELECT server_id, MAX(recorded_at) as max_recorded_at
      FROM health_snapshots
      GROUP BY server_id
    ) latest ON h.server_id = latest.server_id AND h.recorded_at = latest.max_recorded_at
  `).get();

  // Incidents last 24h and 7d
  const incidents24h = db.prepare(
    "SELECT COUNT(*) as count FROM incidents WHERE created_at >= datetime('now', '-1 day')"
  ).get();
  const incidents7d = db.prepare(
    "SELECT COUNT(*) as count FROM incidents WHERE created_at >= datetime('now', '-7 days')"
  ).get();

  // Total scheduled ops run
  const scheduledOpsRun = db.prepare(
    "SELECT COUNT(*) as count FROM scheduled_ops WHERE last_run IS NOT NULL"
  ).get();

  // Total backups
  const totalBackups = db.prepare(
    "SELECT COUNT(*) as count FROM agent_backups WHERE status = 'completed'"
  ).get();

  // Uptime percentage per server (based on health snapshot history, last 7 days)
  const servers = db.prepare('SELECT id, name FROM servers').all();
  const uptimeByServer = [];
  for (const s of servers) {
    const totalSnapshots = db.prepare(
      "SELECT COUNT(*) as count FROM health_snapshots WHERE server_id = ? AND recorded_at >= datetime('now', '-7 days')"
    ).get(s.id);
    // If we have snapshots, the server was online. Compare to expected (~every 30s = ~20160 in 7 days)
    // More practically: count snapshots vs expected based on poll interval
    const expectedPolls = 7 * 24 * 60 * 2; // one poll every 30s
    const uptimePct = totalSnapshots.count > 0
      ? Math.min(100, (totalSnapshots.count / expectedPolls) * 100).toFixed(1)
      : 0;
    uptimeByServer.push({ server_id: s.id, server_name: s.name, uptime_pct: parseFloat(uptimePct), snapshots: totalSnapshots.count });
  }

  // Incident breakdown by type
  const incidentTypes = db.prepare(`
    SELECT type, severity, COUNT(*) as count
    FROM incidents
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY type, severity
    ORDER BY count DESC
  `).all();

  res.json({
    servers: {
      total: serverStats.total,
      online: serverStats.online,
      offline: serverStats.offline
    },
    averages: {
      cpu: avgMetrics.avg_cpu ? parseFloat(avgMetrics.avg_cpu.toFixed(1)) : null,
      memory_pct: avgMetrics.avg_memory_pct ? parseFloat(avgMetrics.avg_memory_pct.toFixed(1)) : null,
      disk_pct: avgMetrics.avg_disk ? parseFloat(avgMetrics.avg_disk.toFixed(1)) : null
    },
    incidents: {
      last_24h: incidents24h.count,
      last_7d: incidents7d.count,
      by_type: incidentTypes
    },
    scheduled_ops_run: scheduledOpsRun.count,
    total_backups: totalBackups.count,
    uptime_by_server: uptimeByServer
  });
});

/**
 * GET /api/v1/servers/:id/analytics — per-server analytics
 */
router.get('/servers/:id/analytics', authenticate, (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }

  // CPU/RAM/disk hourly averages for last 24h
  const hourlyTrends = db.prepare(`
    SELECT
      strftime('%Y-%m-%d %H:00', recorded_at) as hour,
      AVG(cpu_percent) as avg_cpu,
      AVG(CASE WHEN memory_total_mb > 0 THEN memory_used_mb * 100.0 / memory_total_mb ELSE NULL END) as avg_memory_pct,
      AVG(disk_percent) as avg_disk,
      COUNT(*) as sample_count
    FROM health_snapshots
    WHERE server_id = ? AND recorded_at >= datetime('now', '-24 hours')
    GROUP BY strftime('%Y-%m-%d %H:00', recorded_at)
    ORDER BY hour ASC
  `).all(req.params.id);

  // Incident count and types for this server
  const incidents = db.prepare(`
    SELECT type, severity, COUNT(*) as count
    FROM incidents
    WHERE server_id = ? AND created_at >= datetime('now', '-7 days')
    GROUP BY type, severity
    ORDER BY count DESC
  `).all(req.params.id);

  const totalIncidents = db.prepare(
    "SELECT COUNT(*) as count FROM incidents WHERE server_id = ? AND created_at >= datetime('now', '-7 days')"
  ).get(req.params.id);

  const activeIncidents = db.prepare(
    'SELECT COUNT(*) as count FROM incidents WHERE server_id = ? AND resolved = 0'
  ).get(req.params.id);

  // Usage tracking data (if any)
  const usageToday = db.prepare(
    "SELECT SUM(api_calls) as api_calls, SUM(tokens_in) as tokens_in, SUM(tokens_out) as tokens_out, SUM(estimated_cost) as cost FROM usage_tracking WHERE server_id = ? AND date = date('now')"
  ).get(req.params.id);

  const usageWeek = db.prepare(
    "SELECT SUM(api_calls) as api_calls, SUM(tokens_in) as tokens_in, SUM(tokens_out) as tokens_out, SUM(estimated_cost) as cost FROM usage_tracking WHERE server_id = ? AND date >= date('now', '-7 days')"
  ).get(req.params.id);

  const usageMonth = db.prepare(
    "SELECT SUM(api_calls) as api_calls, SUM(tokens_in) as tokens_in, SUM(tokens_out) as tokens_out, SUM(estimated_cost) as cost FROM usage_tracking WHERE server_id = ? AND date >= date('now', '-30 days')"
  ).get(req.params.id);

  res.json({
    server_id: server.id,
    server_name: server.name,
    hourly_trends: hourlyTrends.map(h => ({
      hour: h.hour,
      cpu: h.avg_cpu ? parseFloat(h.avg_cpu.toFixed(1)) : null,
      memory_pct: h.avg_memory_pct ? parseFloat(h.avg_memory_pct.toFixed(1)) : null,
      disk_pct: h.avg_disk ? parseFloat(h.avg_disk.toFixed(1)) : null,
      samples: h.sample_count
    })),
    incidents: {
      total_7d: totalIncidents.count,
      active: activeIncidents.count,
      by_type: incidents
    },
    usage: {
      today: {
        api_calls: usageToday?.api_calls || 0,
        tokens_in: usageToday?.tokens_in || 0,
        tokens_out: usageToday?.tokens_out || 0,
        cost: usageToday?.cost || 0
      },
      week: {
        api_calls: usageWeek?.api_calls || 0,
        tokens_in: usageWeek?.tokens_in || 0,
        tokens_out: usageWeek?.tokens_out || 0,
        cost: usageWeek?.cost || 0
      },
      month: {
        api_calls: usageMonth?.api_calls || 0,
        tokens_in: usageMonth?.tokens_in || 0,
        tokens_out: usageMonth?.tokens_out || 0,
        cost: usageMonth?.cost || 0
      }
    }
  });
});

export default router;
