import crypto from 'crypto';
import { db } from '../db/init.js';

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
        // Record snapshot
        db.prepare(`
          INSERT INTO health_snapshots (id, server_id, cpu_percent, memory_used_mb, memory_total_mb,
            disk_used_gb, disk_total_gb, disk_percent, uptime)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          crypto.randomUUID(),
          server.id,
          stats.cpu_percent ?? stats.cpu ?? null,
          stats.memory_used_mb ?? stats.mem_used ?? null,
          stats.memory_total_mb ?? stats.mem_total ?? null,
          stats.disk_used_gb ?? null,
          stats.disk_total_gb ?? null,
          stats.disk_percent ?? stats.disk ?? null,
          stats.uptime ?? null
        );

        // Update server status
        db.prepare(
          "UPDATE servers SET status = ?, last_seen = datetime('now') WHERE id = ?"
        ).run('online', server.id);
      } else {
        // No response — check if we should mark offline
        if (server.status === 'online') {
          db.prepare(
            'UPDATE servers SET status = ? WHERE id = ?'
          ).run('offline', server.id);
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
