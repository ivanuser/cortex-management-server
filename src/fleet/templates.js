import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load templates from JSON file
let templates = [];
try {
  const raw = readFileSync(path.join(__dirname, 'templates.json'), 'utf-8');
  templates = JSON.parse(raw);
} catch (err) {
  console.error('Failed to load templates.json:', err.message);
}

/**
 * Get all available server templates
 */
export function getTemplates() {
  return templates;
}

/**
 * Get a specific template by ID
 */
export function getTemplate(templateId) {
  return templates.find(t => t.id === templateId) || null;
}

/**
 * Send template setup commands to a newly registered server
 */
export async function applyTemplate(server, templateId) {
  const template = getTemplate(templateId);
  if (!template) return;

  if (!server.gateway_url || !server.gateway_token) {
    console.log(`[Templates] Cannot apply template to ${server.name} — no gateway`);
    return;
  }

  console.log(`📋 [Templates] Applying "${template.name}" to ${server.name}`);

  // Send setup commands with a delay between each
  for (let i = 0; i < template.setup_commands.length; i++) {
    const command = template.setup_commands[i];
    setTimeout(() => {
      sendTemplateCommand(server, command, template.name);
    }, (i + 1) * 10_000); // 10s between commands
  }
}

/**
 * Send a single template command to a server
 */
async function sendTemplateCommand(server, command, templateName) {
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
          client: { id: 'template-setup', displayName: 'Template Setup', version: '1.0.0', platform: 'server', mode: 'webchat' },
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
            type: 'req', method: 'chat.send', id: 'template-' + crypto.randomUUID(),
            params: {
              sessionKey: 'agent:main:webchat',
              message: `[TEMPLATE: ${templateName}] ${command}`,
              idempotencyKey: crypto.randomUUID()
            }
          }));
          console.log(`📋 [Templates] Sent to ${server.name}: ${command}`);
          setTimeout(() => ws.close(), 5000);
        }
        if (msg.type === 'event' && msg.event === 'connect.challenge') {
          ws.send(JSON.stringify({
            type: 'req', id: 'connect', method: 'connect',
            params: {
              minProtocol: 3, maxProtocol: 3,
              client: { id: 'template-setup', displayName: 'Template Setup', version: '1.0.0', platform: 'server', mode: 'webchat' },
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
    console.error(`[Templates] Failed to send to ${server.name}:`, err.message);
  }
}

export default { getTemplates, getTemplate, applyTemplate };
