import crypto from 'crypto';
import { db } from '../db/init.js';
import { fireWebhookEvent } from './webhooks.js';

const POLL_INTERVAL = 30_000; // 30 seconds
let pollTimer = null;

/**
 * Fetch health stats from a single server's /stats.json endpoint
 */
async function fetchServerHealth(server) {
  if (!server.gateway_url) return null;

  const url = server.gateway_url.replace(/\/+$/, '') + '/stats.json';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Fetch skills count from a server's /skills.json endpoint
 */
async function fetchServerSkills(server) {
  if (!server.gateway_url) return null;

  const url = server.gateway_url.replace(/\/+$/, '') + '/skills.json';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json();
    return {
      count: data.count || (data.installed ? data.installed.length : 0),
      skills: data.installed || []
    };
  } catch {
    return null;
  }
}

/**
 * Poll all registered servers for health data
 */
async function pollAll() {
  const servers = db.prepare(
    'SELECT id, name, gateway_url, status FROM servers'
  ).all();

  for (const server of servers) {
    try {
      const stats = await fetchServerHealth(server);

      if (stats) {
        // Extract from nested stats.json format
        const cpu = stats.cpu?.percent ?? stats.cpu_percent ?? stats.cpu ?? null;
        const memUsed = stats.memory?.used ?? stats.memory_used_mb ?? null;
        const memTotal = stats.memory?.total ?? stats.memory_total_mb ?? null;
        const diskUsed = stats.disk?.used ?? stats.disk_used_gb ?? null;
        const diskTotal = stats.disk?.total ?? stats.disk_total_gb ?? null;
        const diskPct = stats.disk?.percent ?? stats.disk_percent ?? null;
        const uptime = stats.uptime ?? null;

        // Record snapshot
        db.prepare(`
          INSERT INTO health_snapshots (id, server_id, cpu_percent, memory_used_mb, memory_total_mb,
            disk_used_gb, disk_total_gb, disk_percent, uptime)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          crypto.randomUUID(),
          server.id,
          cpu, memUsed, memTotal, diskUsed, diskTotal, diskPct, uptime
        );

        // Update server status
        if (server.status !== 'online') {
          fireWebhookEvent('server_online', { server_id: server.id, server_name: server.name });
        }
        db.prepare(
          "UPDATE servers SET status = ?, last_seen = datetime('now') WHERE id = ?"
        ).run('online', server.id);

        // Fetch skills count (non-blocking, don't fail health poll if this fails)
        try {
          const skillsData = await fetchServerSkills(server);
          if (skillsData) {
            db.prepare(
              'UPDATE servers SET skills_count = ? WHERE id = ?'
            ).run(skillsData.count, server.id);
          }
        } catch {}
      } else {
        // No response — check if we should mark offline
        if (server.status === 'online') {
          db.prepare(
            'UPDATE servers SET status = ? WHERE id = ?'
          ).run('offline', server.id);
          fireWebhookEvent('server_offline', { server_id: server.id, server_name: server.name });
        }
      }
    } catch (err) {
      console.error(`Health poll error for ${server.name}:`, err.message);
    }
  }

  // Prune old snapshots (keep last 7 days)
  db.prepare(
    "DELETE FROM health_snapshots WHERE recorded_at < datetime('now', '-7 days')"
  ).run();
}

/**
 * Start the health poller
 */
export function startHealthPoller() {
  console.log('🔄 Health poller started (every 30s)');
  // Initial poll after 5 seconds
  setTimeout(pollAll, 5_000);
  pollTimer = setInterval(pollAll, POLL_INTERVAL);
}

/**
 * Stop the health poller
 */
export function stopHealthPoller() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
    console.log('⏹️  Health poller stopped');
  }
}

export default { startHealthPoller, stopHealthPoller };
