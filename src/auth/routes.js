import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { authenticator } from 'otplib';
import { db, config } from '../db/init.js';
import { authenticate, requireRole } from './middleware.js';

const router = Router();

// Helper to log audit events
function audit(userId, action, details, ip, serverId = null) {
  db.prepare(
    'INSERT INTO audit_log (id, user_id, server_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), userId, serverId, action, details, ip);
}

/**
 * POST /api/v1/auth/login
 * Authenticate with username/password, optionally verify TOTP
 */
router.post('/login', (req, res) => {
  const { username, password, totpCode } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = db.prepare(
    'SELECT * FROM users WHERE username = ? AND active = 1'
  ).get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Check TOTP if enabled
  if (user.totp_enabled) {
    if (!totpCode) {
      return res.status(200).json({ requires2FA: true, message: '2FA code required' });
    }
    const valid = authenticator.check(totpCode, user.totp_secret);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
  }

  // Generate JWT
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    config.jwtSecret,
    { expiresIn: '24h' }
  );

  // Update last_login
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);
  audit(user.id, 'login', `User ${username} logged in`, req.ip);

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      totp_enabled: !!user.totp_enabled
    }
  });
});

/**
 * POST /api/v1/auth/logout
 */
router.post('/logout', authenticate, (req, res) => {
  audit(req.user.id, 'logout', `User ${req.user.username} logged out`, req.ip);
  // JWT is stateless — client should discard the token
  res.json({ message: 'Logged out' });
});

/**
 * GET /api/v1/auth/me
 */
router.get('/me', authenticate, (req, res) => {
  const user = db.prepare(
    'SELECT id, username, role, totp_enabled, created_at, last_login FROM users WHERE id = ?'
  ).get(req.user.id);
  res.json(user);
});

/**
 * PUT /api/v1/auth/password
 */
router.put('/password', authenticate, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Current password incorrect' });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  audit(req.user.id, 'password_change', 'Password changed', req.ip);

  res.json({ message: 'Password updated' });
});

/**
 * POST /api/v1/auth/2fa/setup
 * Generate a TOTP secret for the user
 */
router.post('/2fa/setup', authenticate, (req, res) => {
  const secret = authenticator.generateSecret();
  const otpauthUrl = authenticator.keyuri(req.user.username, 'CortexOS Management', secret);

  // Store secret but don't enable yet (user must verify first)
  db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret, req.user.id);

  res.json({ secret, otpauthUrl });
});

/**
 * POST /api/v1/auth/2fa/verify
 * Verify a TOTP code and enable 2FA
 */
router.post('/2fa/verify', authenticate, (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Verification code required' });
  }

  const user = db.prepare('SELECT totp_secret FROM users WHERE id = ?').get(req.user.id);
  if (!user.totp_secret) {
    return res.status(400).json({ error: 'Run 2FA setup first' });
  }

  const valid = authenticator.check(code, user.totp_secret);
  if (!valid) {
    return res.status(400).json({ error: 'Invalid code — try again' });
  }

  db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').run(req.user.id);
  audit(req.user.id, '2fa_enabled', '2FA enabled', req.ip);

  res.json({ message: '2FA enabled successfully' });
});

/**
 * POST /api/v1/auth/2fa/disable
 * Disable 2FA (requires current password)
 */
router.post('/2fa/disable', authenticate, (req, res) => {
  const { password } = req.body || {};

  if (!password) {
    return res.status(400).json({ error: 'Current password required to disable 2FA' });
  }

  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  db.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?').run(req.user.id);
  audit(req.user.id, '2fa_disabled', '2FA disabled', req.ip);
  res.json({ message: '2FA disabled' });
});

/**
 * GET /api/v1/auth/users (admin only)
 */
router.get('/users', authenticate, requireRole('admin'), (req, res) => {
  const users = db.prepare(
    'SELECT id, username, role, totp_enabled, created_at, last_login, active FROM users ORDER BY created_at DESC'
  ).all();
  res.json(users);
});

/**
 * POST /api/v1/auth/users (admin only) — create user
 */
router.post('/users', authenticate, requireRole('admin'), (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  const id = crypto.randomUUID();
  const hash = bcrypt.hashSync(password, 10);
  const userRole = role || 'viewer';

  db.prepare(
    'INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)'
  ).run(id, username, hash, userRole);

  audit(req.user.id, 'user_created', `Created user: ${username} (${userRole})`, req.ip);

  res.status(201).json({ id, username, role: userRole });
});

/**
 * PUT /api/v1/auth/users/:id (admin only) — update user role/active status
 */
router.put('/users/:id', authenticate, requireRole('admin'), (req, res) => {
  const { role, active } = req.body;

  const user = db.prepare('SELECT id, username, role, active FROM users WHERE id = ?').get(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Don't allow admins to demote themselves
  if (req.params.id === req.user.id && role && role !== 'admin') {
    return res.status(400).json({ error: 'Cannot change your own role' });
  }

  const validRoles = ['admin', 'operator', 'viewer'];
  if (role && !validRoles.includes(role)) {
    return res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
  }

  const newRole = role || user.role;
  const newActive = active !== undefined ? (active ? 1 : 0) : user.active;

  db.prepare('UPDATE users SET role = ?, active = ? WHERE id = ?').run(newRole, newActive, req.params.id);

  const changes = [];
  if (role && role !== user.role) changes.push(`role: ${user.role} → ${role}`);
  if (active !== undefined && (active ? 1 : 0) !== user.active) changes.push(`active: ${!!user.active} → ${!!active}`);
  audit(req.user.id, 'user_modified', `Modified user ${user.username}: ${changes.join(', ')}`, req.ip);

  res.json({ message: 'User updated', id: user.id, username: user.username, role: newRole, active: !!newActive });
});

/**
 * DELETE /api/v1/auth/users/:id (admin only)
 */
router.delete('/users/:id', authenticate, requireRole('admin'), (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }

  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'user_deleted', `Deactivated user: ${user.username}`, req.ip);

  res.json({ message: 'User deactivated' });
});

export default router;
