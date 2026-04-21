const { v4: uuidv4 } = require('uuid');
const supabase = require('../config/supabase');
const { generateApiKey } = require('../services/apiKeyService');

// ─── POST /api/keys/generate ─────────────────────────────────
exports.generate = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { name, plan } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'API key name is required.' });
    }

    const PLAN_LIMITS = {
      starter: 500,
      pro: 5000,
      business: 25000,
      enterprise: 999999
    };

    if (!plan || !PLAN_LIMITS[plan]) {
      return res.status(400).json({ error: 'A valid plan is required. Choose from: starter, pro, business, enterprise.' });
    }

    const { rawKey, hash, preview } = generateApiKey();

    const { data: apiKey, error } = await supabase
      .from('api_keys')
      .insert({
        id: uuidv4(),
        user_id: userId,
        name: name.trim(),
        key_hash: hash,
        key_preview: preview,
        plan,
        scans_used: 0,
        scans_limit: PLAN_LIMITS[plan],
        is_active: true
      })
      .select('id, name, key_preview, plan, scans_limit, created_at')
      .single();

    if (error) throw error;

    return res.status(201).json({
      message: 'API key created successfully. This is the ONLY time your full key will be shown — store it safely.',
      key: rawKey,
      apiKey
    });
  } catch (err) {
    next(err);
  }
};

// ─── GET /api/keys/list ──────────────────────────────────────
exports.list = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const { data: keys, error } = await supabase
      .from('api_keys')
      .select('id, name, key_preview, plan, scans_used, scans_limit, is_active, last_used_at, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    return res.status(200).json({ keys });
  } catch (err) {
    next(err);
  }
};

// ─── DELETE /api/keys/:id/revoke ─────────────────────────────
exports.revoke = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    const { data: updated, error } = await supabase
      .from('api_keys')
      .update({ is_active: false })
      .eq('id', id)
      .eq('user_id', userId)
      .select()
      .single();

    if (error) {
      return res.status(404).json({ error: 'API key not found or does not belong to you.' });
    }

    return res.status(200).json({ message: 'API key revoked successfully.', apiKey: updated });
  } catch (err) {
    next(err);
  }
};
