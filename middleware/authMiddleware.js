require('dotenv').config();
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

/**
 * Middleware: Verify JWT from Authorization header.
 * Attaches decoded payload to req.user on success.
 * Returns 401 if token is missing, malformed, or invalid.
 */
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  // Expect header format: "Bearer <token>"
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token is required.' });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authorization token is missing.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, iat, exp }
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token has expired. Please log in again.' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token.' });
    }
    // Unexpected JWT error
    return res.status(401).json({ error: 'Authentication failed.' });
  }
};

module.exports = authMiddleware;
