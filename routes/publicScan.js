const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const supabase = require('../config/supabase');
const apiKeyMiddleware = require('../middleware/apiKeyMiddleware');
const masterScanner = require('../services/masterScanner');

// ─── POST /api/public/scan ───────────────────────────────────
// Authenticated via API key, no domain ownership check required.
router.post('/scan', apiKeyMiddleware, async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'URL is required in request body.' });
    }

    const userId = req.user.id;
    const apiKeyId = req.apiKey.id;

    // Run the full scan
    const report = await masterScanner(url, userId);

    // Increment scans_used and update last_used_at
    await supabase
      .from('api_keys')
      .update({
        scans_used: req.apiKey.scans_used + 1,
        last_used_at: new Date().toISOString()
      })
      .eq('id', apiKeyId);

    // Log usage
    await supabase
      .from('api_usage_logs')
      .insert({
        id: uuidv4(),
        api_key_id: apiKeyId,
        user_id: userId,
        scanned_url: url,
        scan_id: report.scan_id || null,
        status_code: 200
      });

    return res.status(200).json(report);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
