import crypto from 'crypto';
import { db } from '../db/init.js';
import { fireWebhookEvent } from './webhooks.js';

// Track consecutive high-CPU polls per server
const cpuHistory = new Map(); // serverId -> count of consecutive high-CPU polls
const offlineTimers = new Map(); // serverId -> timestamp when first went offline

const INCIDENT_POLL_INTERVAL = 30_000; // 30 seconds, same as health poller
let incidentTimer = null;

/**
 * Check health snapshots for critical conditions and create incidents
 */
async function checkIncidents() {
  const servers = db.prepare(
    'SELECT id, name, status, last_seen, gateway_url, gateway_token FROM servers'
  ).all();

  for (const server of servers) {
    try {
      // Get latest health snapshot
      const latest = db.prepare(
        'SELECT * FROM health_snapshots WHERE server_id = ? ORDER BY recorded_at DESC LIMIT 1'
      ).get(server.id);

      // --- CPU > 95% for 3+ consecutive polls ---
      if (latest?.cpu_percent != null && latest.cpu_percent > 95) {
        const count = (cpuHistory.get(server.id) || 0) + 1;
        cpuHistory.set(server.id, count);
        if (count >= 3) {
          await createIncidentIfNew(server, 'high_cpu', 'critical',
            `CPU at ${Math.round(latest.cpu_percent)}% for ${count} consecutive polls`,
            'Identify and report the top CPU-consuming processes');
        }
      } else {
        cpuHistory.set(server.id, 0);
        // Auto-resolve high_cpu if it drops
        resolveIncidents(server.id, 'high_cpu');
      }

      // --- Memory > 95% ---
      if (latest?.memory_used_mb && latest?.memory_total_mb) {
        const memPct = (latest.memory_used_mb / latest.memory_total_mb) * 100;
        if (memPct > 95) {
          await createIncidentIfNew(server, 'high_memory', 'critical',
            `Memory at ${Math.round(memPct)}% (${Math.round(latest.memory_used_mb)}/${Math.round(latest.memory_total_mb)} MB)`,
            'Identify memory hogs and suggest what to restart');
        } else {
          resolveIncidents(server.id, 'high_memory');
        }
      }

      // --- Disk > 90% ---
      if (latest?.disk_percent != null && latest.disk_percent > 90) {
        await createIncidentIfNew(server, 'high_disk', 'warning',
          `Disk at ${Math.round(latest.disk_percent)}%`,
          'Run disk cleanup — clear apt cache, old logs, docker prune');
      } else if (latest?.disk_percent != null) {
        resolveIncidents(server.id, 'high_disk');
      }

      // --- Server offline for 5+ minutes ---
      if (server.status === 'offline') {
        if (!offlineTimers.has(server.id)) {
          offlineTimers.set(server.id, Date.now());
        }
        const offlineSince = offlineTimers.get(server.id);
        const offlineMinutes = (Date.now() - offlineSince) / 60_000;
        if (offlineMinutes >= 5) {
          await createIncidentIfNew(server, 'server_offline', 'critical',
            `Server offline for ${Math.round(offlineMinutes)} minutes`,
            null); // Can't send commands to offline server
        }
      } else {
        if (offlineTimers.has(server.id)) {
          offlineTimers.delete(server.id);
          resolveIncidents(server.id, 'server_offline');
        }
      }
    } catch (err) {
      console.error(`[Incident] Error checking ${server.name}:`, err.message);
    }
  }
}

/**
 * Create an incident if there isn't an active (unresolved) one of the same type for this server
 */
async function createIncidentIfNew(server, type, severity, message, autoAction) {
  // Check for existing unresolved incident of same type
  const existing = db.prepare(
    'SELECT id FROM incidents WHERE server_id = ? AND type = ? AND resolved = 0'
  ).get(server.id, type);

  if (existing) return; // Already have an active incident

  const id = crypto.randomUUID();
  db.prepare(
    'INSERT INTO incidents (id, server_id, type, severity, message, auto_action) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, server.id, type, severity, message, autoAction || null);

  console.log(`🚨 [Incident] ${severity.toUpperCase()}: ${server.name} — ${message}`);

  // Fire webhook
  const webhookEvent = severity === 'critical' ? 'incident_critical' : 'incident_warning';
  fireWebhookEvent(webhookEvent, {
    server_id: server.id,
    server_name: server.name,
    incident_id: id,
    type,
    severity,
    message,
    auto_action: autoAction
  });

  // Send auto-remediation command if server is reachable
  if (autoAction && server.gateway_url && server.gateway_token && server.status !== 'offline') {
    sendRemediationCommand(server, autoAction, id);
  }
}

/**
 * Send a remediation command to the server via its gateway WebSocket
 */
async function sendRemediationCommand(server, command, incidentId) {
  try {
    const { WebSocket } = await import('ws');
    const gwUrl = server.gateway_url.replace(/^http/, 'ws').replace(/\/$/, '');

    const ws = new WebSocket(gwUrl);
    let connected = false;

    const timeout = setTimeout(() => {
      if (!connected) {
        ws.close();
        console.error(`[Incident] Remediation timeout for ${server.name}`);
      }
    }, 15_000);

    ws.on('open', () => {
      // Send connect request
      ws.send(JSON.stringify({
        type: 'req', id: 'connect', method: 'connect',
        params: {
          minProtocol: 3, maxProtocol: 3,
          client: { id: 'incident-response', displayName: 'Incident Response', version: '1.0.0', platform: 'server', mode: 'webchat' },
          scopes: ['operator.admin'],
          auth: { token: server.gateway_token }
        }
      }));
    });

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());

        // Handle connect response
        if (msg.type === 'res' && msg.id === 'connect') {
          if (msg.ok) {
            connected = true;
            // Send the remediation command
            ws.send(JSON.stringify({
              type: 'req', method: 'chat.send', id: 'remediate-' + incidentId,
              params: {
                sessionKey: 'agent:main:webchat',
                message: `[AUTO-INCIDENT-RESPONSE] ${command}`,
                idempotencyKey: crypto.randomUUID()
              }
            }));
            console.log(`[Incident] Sent remediation to ${server.name}: ${command}`);
            // Close after sending
            setTimeout(() => ws.close(), 5000);
          } else {
            console.error(`[Incident] Auth failed for ${server.name}`);
            ws.close();
          }
        }

        // Handle challenge
        if (msg.type === 'event' && msg.event === 'connect.challenge') {
          ws.send(JSON.stringify({
            type: 'req', id: 'connect', method: 'connect',
            params: {
              minProtocol: 3, maxProtocol: 3,
              client: { id: 'incident-response', displayName: 'Incident Response', version: '1.0.0', platform: 'server', mode: 'webchat' },
              scopes: ['operator.admin'],
              auth: { token: server.gateway_token }
            }
          }));
        }
      } catch {}
    });

    ws.on('error', (err) => {
      console.error(`[Incident] WS error for ${server.name}:`, err.message);
    });

    ws.on('close', () => {
      clearTimeout(timeout);
    });
  } catch (err) {
    console.error(`[Incident] Failed to send remediation to ${server.name}:`, err.message);
  }
}

/**
 * Resolve all active incidents of a given type for a server
 */
function resolveIncidents(serverId, type) {
  const resolved = db.prepare(
    "UPDATE incidents SET resolved = 1, resolved_at = datetime('now') WHERE server_id = ? AND type = ? AND resolved = 0"
  ).run(serverId, type);

  if (resolved.changes > 0) {
    console.log(`✅ [Incident] Resolved ${resolved.changes} ${type} incident(s) for server ${serverId}`);
  }
}

/**
 * Get active incident count for a server
 */
export function getActiveIncidentCount(serverId) {
  const row = db.prepare(
    'SELECT COUNT(*) as count FROM incidents WHERE server_id = ? AND resolved = 0'
  ).get(serverId);
  return row?.count || 0;
}

/**
 * Get all active incidents across the fleet
 */
export function getAllActiveIncidents() {
  return db.prepare(`
    SELECT i.*, s.name as server_name
    FROM incidents i
    JOIN servers s ON s.id = i.server_id
    WHERE i.resolved = 0
    ORDER BY i.created_at DESC
  `).all();
}

/**
 * Start the incident monitor
 */
export function startIncidentMonitor() {
  console.log('🚨 Incident monitor started (every 30s)');
  setTimeout(checkIncidents, 10_000); // Initial check after 10s
  incidentTimer = setInterval(checkIncidents, INCIDENT_POLL_INTERVAL);
}

/**
 * Stop the incident monitor
 */
export function stopIncidentMonitor() {
  if (incidentTimer) {
    clearInterval(incidentTimer);
    incidentTimer = null;
    console.log('⏹️  Incident monitor stopped');
  }
}

export default { startIncidentMonitor, stopIncidentMonitor, getActiveIncidentCount, getAllActiveIncidents };
