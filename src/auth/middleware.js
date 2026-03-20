import jwt from 'jsonwebtoken';
import { db, config } from '../db/init.js';

/**
 * JWT authentication middleware.
 * Checks Authorization header (Bearer token) or 'token' cookie.
 */
export function authenticate(req, res, next) {
  let token = null;

  // Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  // Fallback to cookie
  if (!token && req.cookies) {
    token = req.cookies.token;
  }

  // Fallback to query param (for SSE / EventSource)
  if (!token && req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const payload = jwt.verify(token, config.jwtSecret);
    const user = db.prepare(
      'SELECT id, username, role, totp_enabled, active FROM users WHERE id = ?'
    ).get(payload.userId);

    if (!user || !user.active) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/**
 * Role-checking middleware factory.
 * Usage: requireRole('admin')
 */
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

export default authenticate;
