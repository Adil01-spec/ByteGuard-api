const rateLimit = require('express-rate-limit');

// 1. Strict Auth Limiter (max 5 per 15 minutes per IP on /login and /register)
const authStrictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per `window`
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again after 15 minutes.' },
  statusCode: 429
});

// 2. Global Auth IP Tracker Limiter (max 20 FAILED requests per 1 hour)
const globalAuthFailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit each IP to 20 failed requests per `window`
  skipSuccessfulRequests: true, // Only count failed status codes (>= 400)
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'IP temporarily blocked due to excessive failed authentication attempts. Please try again later.' },
  statusCode: 429
});

module.exports = {
  authStrictLimiter,
  globalAuthFailLimiter
};
