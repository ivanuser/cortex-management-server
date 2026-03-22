import { db } from '../db/init.js';

/**
 * Supported webhook events
 */
export const WEBHOOK_EVENTS = [
  'server_offline',
  'server_online',
  'incident_critical',
  'incident_warning',
  'backup_complete',
  'scheduled_op_complete'
];

/**
 * Fire a webhook event — sends to all enabled webhooks subscribed to this event
 */
export async function fireWebhookEvent(eventName, payload) {
  try {
    const webhooks = db.prepare(
      'SELECT * FROM webhooks WHERE enabled = 1'
    ).all();

    for (const wh of webhooks) {
      const events = JSON.parse(wh.events || '[]');
      if (!events.includes(eventName)) continue;

      // Fire async, don't await (fire-and-forget)
      sendWebhookPayload(wh, eventName, payload).catch(err => {
        console.error(`[Webhook] Failed to send to ${wh.name}:`, err.message);
      });
    }
  } catch (err) {
    console.error('[Webhook] Error firing event:', err.message);
  }
}

/**
 * Send payload to a single webhook URL
 */
async function sendWebhookPayload(webhook, eventName, payload) {
  const isDiscord = webhook.url.includes('discord.com/api/webhooks');

  const timestamp = new Date().toISOString();
  const severityEmoji = {
    incident_critical: '🔴',
    incident_warning: '🟡',
    server_offline: '⚫',
    server_online: '🟢',
    backup_complete: '💾',
    scheduled_op_complete: '📅'
  };

  let body;

  if (isDiscord) {
    // Discord webhook format
    const emoji = severityEmoji[eventName] || '📣';
    let content = `${emoji} **CortexOS Alert: ${eventName.replace(/_/g, ' ').toUpperCase()}**\n`;

    if (payload.server_name) content += `**Server:** ${payload.server_name}\n`;
    if (payload.message) content += `**Details:** ${payload.message}\n`;
    if (payload.auto_action) content += `**Auto-action:** ${payload.auto_action}\n`;
    if (payload.type) content += `**Type:** ${payload.type}\n`;

    content += `\n_${timestamp}_`;

    body = JSON.stringify({ content });
  } else {
    // Generic JSON webhook
    body = JSON.stringify({
      event: eventName,
      timestamp,
      payload
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const res = await fetch(webhook.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: controller.signal
    });

    if (!res.ok) {
      console.error(`[Webhook] ${webhook.name} returned ${res.status}`);
    }
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Send a test webhook notification
 */
export async function sendTestWebhook(webhook) {
  return sendWebhookPayload(webhook, 'test', {
    server_name: 'Test Server',
    message: 'This is a test notification from CortexOS Management Server',
    type: 'test',
    severity: 'info'
  });
}

export default { fireWebhookEvent, sendTestWebhook, WEBHOOK_EVENTS };
