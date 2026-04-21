const supabase = require('../config/supabase');
const { hashApiKey } = require('../services/apiKeyService');

/**
 * Middleware that authenticates requests via API key in the Authorization header.
 * Expected format: Authorization: Bearer bg_live_xxxxxxxx
 */
const apiKeyMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or malformed API key. Use Authorization: Bearer <your_api_key>' });
    }

    const rawKey = authHeader.split(' ')[1];

    if (!rawKey || !rawKey.startsWith('bg_live_')) {
      return res.status(401).json({ error: 'Invalid API key format.' });
    }

    const keyHash = hashApiKey(rawKey);

    const { data: apiKey, error } = await supabase
      .from('api_keys')
      .select('*')
      .eq('key_hash', keyHash)
      .maybeSingle();

    if (error) throw error;

    if (!apiKey) {
      return res.status(401).json({ error: 'Invalid API key.' });
    }

    if (!apiKey.is_active) {
      return res.status(401).json({ error: 'This API key has been revoked.' });
    }

    if (apiKey.scans_used >= apiKey.scans_limit) {
      return res.status(429).json({ error: 'Scan limit reached. Please upgrade your plan.' });
    }

    req.apiKey = apiKey;
    req.user = { id: apiKey.user_id };
    next();
  } catch (err) {
    console.error('API Key auth error:', err.message);
    return res.status(500).json({ error: 'Internal authentication error.' });
  }
};

module.exports = apiKeyMiddleware;
