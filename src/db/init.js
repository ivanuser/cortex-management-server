import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, '..', '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'cortex-management.db');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Load or generate config
function loadConfig() {
  if (fs.existsSync(CONFIG_PATH)) {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  }
  const config = {
    jwtSecret: crypto.randomBytes(64).toString('hex'),
    port: 9443,
    createdAt: new Date().toISOString()
  };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  return config;
}

const config = loadConfig();
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    display_name TEXT,
    avatar_data TEXT
  );

  CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    gateway_url TEXT,
    gateway_token TEXT,
    agent_name TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_seen TEXT,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    registered_by TEXT,
    tags TEXT DEFAULT '[]',
    config TEXT DEFAULT '{}',
    avatar_data TEXT,
    skills_count INTEGER DEFAULT 0,
    FOREIGN KEY (registered_by) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS install_tokens (
    id TEXT PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    server_name TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used_at TEXT,
    used_by_server TEXT,
    config TEXT DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (used_by_server) REFERENCES servers(id)
  );

  CREATE TABLE IF NOT EXISTS health_snapshots (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    cpu_percent REAL,
    memory_used_mb REAL,
    memory_total_mb REAL,
    disk_used_gb REAL,
    disk_total_gb REAL,
    disk_percent REAL,
    uptime TEXT,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    server_id TEXT,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_health_server_id ON health_snapshots(server_id);
  CREATE INDEX IF NOT EXISTS idx_health_recorded_at ON health_snapshots(recorded_at);
  CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);
  CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);

  -- Phase 4: Incidents
  CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    message TEXT NOT NULL,
    auto_action TEXT,
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_incidents_server_id ON incidents(server_id);
  CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
  CREATE INDEX IF NOT EXISTS idx_incidents_resolved ON incidents(resolved);

  -- Phase 4: Scheduled Operations
  CREATE TABLE IF NOT EXISTS scheduled_ops (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    server_ids TEXT NOT NULL DEFAULT '*',
    command TEXT NOT NULL,
    cron_expr TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    last_run TEXT,
    next_run TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (created_by) REFERENCES users(id)
  );

  -- Phase 4: Webhooks
  CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    events TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (created_by) REFERENCES users(id)
  );

  -- Phase 6: Notifications (from server agents)
  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    server_id TEXT,
    type TEXT DEFAULT 'info',
    message TEXT,
    read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_notifications_server_id ON notifications(server_id);

  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    user_id TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_chat_server ON chat_messages(server_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
  CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);

  -- Phase 5: Usage Tracking
  CREATE TABLE IF NOT EXISTS usage_tracking (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    date TEXT NOT NULL,
    api_calls INTEGER DEFAULT 0,
    tokens_in INTEGER DEFAULT 0,
    tokens_out INTEGER DEFAULT 0,
    estimated_cost REAL DEFAULT 0,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_usage_server_id ON usage_tracking(server_id);
  CREATE INDEX IF NOT EXISTS idx_usage_date ON usage_tracking(date);
`);

// ─── Schema Migrations ──────────────────────────────────────
// Auto-migrate: add columns that may not exist in older databases
const migrations = [
  { table: 'servers', column: 'avatar_data', sql: 'ALTER TABLE servers ADD COLUMN avatar_data TEXT' },
  { table: 'servers', column: 'skills_count', sql: 'ALTER TABLE servers ADD COLUMN skills_count INTEGER DEFAULT 0' },
  { table: 'install_tokens', column: 'config', sql: "ALTER TABLE install_tokens ADD COLUMN config TEXT DEFAULT '{}'" },
  { table: 'users', column: 'display_name', sql: 'ALTER TABLE users ADD COLUMN display_name TEXT' },
  { table: 'users', column: 'avatar_data', sql: 'ALTER TABLE users ADD COLUMN avatar_data TEXT' },
];
for (const m of migrations) {
  try {
    db.prepare(`SELECT ${m.column} FROM ${m.table} LIMIT 0`).get();
  } catch {
    db.exec(m.sql);
    console.log(`✅ Migration: added ${m.column} to ${m.table}`);
  }
}

// Create default admin user if no users exist
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const id = crypto.randomUUID();
  const hash = bcrypt.hashSync('admin', 10);
  db.prepare(
    'INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)'
  ).run(id, 'admin', hash, 'admin');
  console.log('✅ Created default admin user (admin/admin)');
}

export { db, config };
export default db;
