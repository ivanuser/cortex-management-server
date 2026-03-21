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
    active INTEGER NOT NULL DEFAULT 1
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
`);

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
