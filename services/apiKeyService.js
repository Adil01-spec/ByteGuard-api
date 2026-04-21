const crypto = require('crypto');

/**
 * Generates a cryptographically secure API key prefixed with bg_live_
 * @returns {{ rawKey: string, hash: string, preview: string }}
 */
function generateApiKey() {
  const randomHex = crypto.randomBytes(16).toString('hex'); // 32 hex chars
  const rawKey = `bg_live_${randomHex}`;

  const hash = crypto.createHash('sha256').update(rawKey).digest('hex');

  const preview = rawKey.substring(0, 12) + '...';

  return { rawKey, hash, preview };
}

/**
 * Hashes a raw API key for lookup
 * @param {string} rawKey
 * @returns {string}
 */
function hashApiKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

module.exports = { generateApiKey, hashApiKey };
