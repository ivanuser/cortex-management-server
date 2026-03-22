import crypto from 'crypto';
import { db } from '../db/init.js';
import { fireWebhookEvent } from './webhooks.js';

let schedulerTimer = null;

/**
 * Simple cron parser — supports: minute hour day-of-month month day-of-week
 * Special values: *, */N (every N)
 * Returns true if the cron expression matches the given date
 */
function cronMatches(cronExpr, date) {
  const parts = cronExpr.trim().split(/\s+/);
  if (parts.length !== 5) return false;

  const fields = [
    { value: date.getMinutes(), max: 59 },    // minute
    { value: date.getHours(), max: 23 },       // hour
    { value: date.getDate(), max: 31 },        // day of month
    { value: date.getMonth() + 1, max: 12 },   // month (1-12)
    { value: date.getDay(), max: 7 }            // day of week (0=Sun)
  ];

  for (let i = 0; i < 5; i++) {
    if (!fieldMatches(parts[i], fields[i].value, fields[i].max)) {
      return false;
    }
  }
  return true;
}

function fieldMatches(pattern, value, max) {
  if (pattern === '*') return true;

  // */N — every N
  if (pattern.startsWith('*/')) {
    const step = parseInt(pattern.slice(2));
    return !isNaN(step) && step > 0 && value % step === 0;
  }

  // Comma-separated values: 1,5,10
  const values = pattern.split(',');
  for (const v of values) {
    // Range: 1-5
    if (v.includes('-')) {
      const [start, end] = v.split('-').map(Number);
      if (!isNaN(start) && !isNaN(end) && value >= start && value <= end) return true;
    } else {
      if (parseInt(v) === value) return true;
    }
  }
  return false;
}

/**
 * Calculate next run time for a cron expression (approximate, for display)
 */
function calculateNextRun(cronExpr) {
  const now = new Date();
  // Check up to 1440 minutes ahead (24 hours)
  for (let i = 1; i <= 1440; i++) {
    const candidate = new Date(now.getTime() + i * 60_000);
    candidate.setSeconds(0, 0);
    if (cronMatches(cronExpr, candidate)) {
      return candidate.toISOString();
    }
  }
  return null;
}

/**
 * Check and run scheduled operations
 */
async function checkSchedules() {
  const now = new Date();
  now.setSeconds(0, 0); // Normalize to the minute

  const schedules = db.prepare(
    'SELECT * FROM scheduled_ops WHERE enabled = 1'
  ).all();

  for (const sched of schedules) {
    if (!cronMatches(sched.cron_expr, now)) continue;

    // Don't run if we already ran this minute
    if (sched.last_run) {
      const lastRun = new Date(sched.last_run + (sched.last_run.endsWith('Z') ? '' : 'Z'));
      if (Math.abs(now.getTime() - lastRun.getTime()) < 60_000) continue;
    }

    console.log(`📅 [Scheduler] Running: ${sched.name}`);

    // Determine target servers
    let targetServers;
    if (sched.server_ids === '*') {
      targetServers = db.prepare(
        'SELECT id, name, gateway_url, gateway_token, status FROM servers'
      ).all();
    } else {
      try {
        const ids = JSON.parse(sched.server_ids);
        if (Array.isArray(ids) && ids.length > 0) {
          const placeholders = ids.map(() => '?').join(',');
          targetServers = db.prepare(
            `SELECT id, name, gateway_url, gateway_token, status FROM servers WHERE id IN (${placeholders})`
          ).all(...ids);
        } else {
          targetServers = [];
        }
      } catch {
        targetServers = [];
      }
    }

    // Send command to each target server
    for (const server of targetServers) {
      if (server.status === 'offline' || !server.gateway_url || !server.gateway_token) {
        console.log(`📅 [Scheduler] Skipping ${server.name} (offline or no gateway)`);
        continue;
      }
      sendScheduledCommand(server, sched.command, sched.name);
    }

    // Update last_run and next_run
    const nextRun = calculateNextRun(sched.cron_expr);
    db.prepare(
      "UPDATE scheduled_ops SET last_run = datetime('now'), next_run = ? WHERE id = ?"
    ).run(nextRun, sched.id);

    // Fire webhook
    fireWebhookEvent('scheduled_op_complete', {
      schedule_name: sched.name,
      command: sched.command,
      target_count: targetServers.length
    });
  }
}

/**
 * Send a scheduled command to a server via WebSocket
 */
async function sendScheduledCommand(server, command, scheduleName) {
  try {
    const { WebSocket } = await import('ws');
    const gwUrl = server.gateway_url.replace(/^http/, 'ws').replace(/\/$/, '');

    const ws = new WebSocket(gwUrl);
    let connected = false;

    const timeout = setTimeout(() => {
      if (!connected) {
        ws.close();
        console.error(`[Scheduler] Timeout connecting to ${server.name}`);
      }
    }, 15_000);

    ws.on('open', () => {
      ws.send(JSON.stringify({
        type: 'req', id: 'connect', method: 'connect',
        params: {
          minProtocol: 3, maxProtocol: 3,
          client: { id: 'scheduler', displayName: 'Scheduler', version: '1.0.0', platform: 'server', mode: 'webchat' },
          scopes: ['operator.admin'],
          auth: { token: server.gateway_token }
        }
      }));
    });

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === 'res' && msg.id === 'connect') {
          if (msg.ok) {
            connected = true;
            ws.send(JSON.stringify({
              type: 'req', method: 'chat.send', id: 'sched-' + crypto.randomUUID(),
              params: {
                sessionKey: 'agent:main:webchat',
                message: `[SCHEDULED: ${scheduleName}] ${command}`,
                idempotencyKey: crypto.randomUUID()
              }
            }));
            console.log(`📅 [Scheduler] Sent to ${server.name}: ${command}`);
            setTimeout(() => ws.close(), 5000);
          } else {
            ws.close();
          }
        }

        if (msg.type === 'event' && msg.event === 'connect.challenge') {
          ws.send(JSON.stringify({
            type: 'req', id: 'connect', method: 'connect',
            params: {
              minProtocol: 3, maxProtocol: 3,
              client: { id: 'scheduler', displayName: 'Scheduler', version: '1.0.0', platform: 'server', mode: 'webchat' },
              scopes: ['operator.admin'],
              auth: { token: server.gateway_token }
            }
          }));
        }
      } catch {}
    });

    ws.on('error', (err) => {
      console.error(`[Scheduler] WS error for ${server.name}:`, err.message);
    });

    ws.on('close', () => clearTimeout(timeout));
  } catch (err) {
    console.error(`[Scheduler] Failed to send to ${server.name}:`, err.message);
  }
}

/**
 * Start the scheduler (checks every minute)
 */
export function startScheduler() {
  console.log('📅 Scheduler started (checks every 60s)');
  // Check after 15 seconds on startup
  setTimeout(checkSchedules, 15_000);
  schedulerTimer = setInterval(checkSchedules, 60_000);

  // Update next_run for all enabled schedules on startup
  const schedules = db.prepare('SELECT id, cron_expr FROM scheduled_ops WHERE enabled = 1').all();
  for (const s of schedules) {
    const nextRun = calculateNextRun(s.cron_expr);
    if (nextRun) {
      db.prepare('UPDATE scheduled_ops SET next_run = ? WHERE id = ?').run(nextRun, s.id);
    }
  }
}

/**
 * Stop the scheduler
 */
export function stopScheduler() {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
    console.log('⏹️  Scheduler stopped');
  }
}

export { calculateNextRun };
export default { startScheduler, stopScheduler };
