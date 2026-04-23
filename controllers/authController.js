const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const supabase = require('../config/supabase');

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// ─── Helpers ─────────────────────────────────────────────────
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// ─── POST /api/auth/register ──────────────────────────────────
exports.register = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Check if user already exists
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({ error: 'Email is already registered.' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert user (defaults to free plan, initialize lockout fields)
    const { data: user, error } = await supabase
      .from('users')
      .insert({ id: randomUUID(), email, password_hash, plan: 'free', failed_attempts: 0, locked_until: null })
      .select('id, email, plan, created_at')
      .single();

    if (error) throw error;

    const token = generateToken({ id: user.id, email: user.email, plan: user.plan });

    return res.status(201).json({ token, user });
  } catch (err) {
    next(err);
  }
};

// ─── POST /api/auth/login ─────────────────────────────────────
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Fetch user by email including lockout fields
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, password_hash, plan, failed_attempts, locked_until')
      .eq('email', email)
      .maybeSingle();

    if (error) throw error;

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const remainingMs = new Date(user.locked_until) - new Date();
      const remainingMins = Math.ceil(remainingMs / 60000);
      return res.status(403).json({ 
        error: `Account temporarily locked due to repeated failed login attempts. Try again in ${remainingMins} minutes.`,
        lockedUntil: user.locked_until,
        failedAttempts: user.failed_attempts || 0
      });
    }

    const currentFailedAttempts = user.failed_attempts || 0;

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!isMatch) {
      const newAttempts = currentFailedAttempts + 1;
      const updates = { failed_attempts: newAttempts };
      
      let errorMsg = 'Invalid email or password.';
      
      if (newAttempts >= 5) {
        // Lock for 30 minutes
        const lockTime = new Date();
        lockTime.setMinutes(lockTime.getMinutes() + 30);
        updates.locked_until = lockTime.toISOString();
        errorMsg = 'Account temporarily locked due to repeated failed login attempts. Try again in 30 minutes.';
      }

      await supabase.from('users').update(updates).eq('id', user.id);

      return res.status(getLockoutCode(newAttempts)).json({ 
        error: errorMsg,
        failedAttempts: newAttempts,
        maxAttempts: 5,
        lockedUntil: updates.locked_until || null
      });
    }

    // Reset attempts on successful login
    if (currentFailedAttempts > 0 || user.locked_until !== null) {
      await supabase.from('users')
        .update({ failed_attempts: 0, locked_until: null })
        .eq('id', user.id);
    }

    const token = generateToken({ id: user.id, email: user.email, plan: user.plan || 'free' });

    return res.status(200).json({
      token,
      user: { id: user.id, email: user.email, plan: user.plan || 'free' },
    });
  } catch (err) {
    next(err);
  }
};

function getLockoutCode(attempts) {
  return attempts >= 5 ? 403 : 401;
}

// ─── GET /api/auth/me ─────────────────────────────────────────
exports.me = async (req, res, next) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, plan, plan_expires_at')
      .eq('id', req.user.id)
      .single();
    
    if (error) throw error;
    res.json(user);
  } catch (err) {
    next(err);
  }
};
