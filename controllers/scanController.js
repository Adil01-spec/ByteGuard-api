const { runFullScan } = require('../services/masterScanner');
const supabase = require('../config/supabase');

/**
 * Extracts the bare hostname from a URL string.
 */
function extractHostname(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return u.hostname;
  } catch {
    return null;
  }
}

// ─── POST /api/scan ───────────────────────────────────────────
exports.runScan = async (req, res, next) => {
  try {
    const { url } = req.body;
    const userId = req.user.id;

    if (!url) {
      return res.status(400).json({ error: 'URL is required.' });
    }

    const hostname = extractHostname(url);
    if (!hostname) {
      return res.status(400).json({ error: 'Invalid URL format.' });
    }

    // Check if this domain is registered AND verified by this user
    const { data: domainRecord, error: fetchError } = await supabase
      .from('domains')
      .select('id, domain, is_verified')
      .eq('user_id', userId)
      .eq('domain', hostname)
      .maybeSingle();

    if (fetchError) throw fetchError;

    if (!domainRecord) {
      return res.status(403).json({
        error: 'Domain not registered.',
        message: `You have not registered "${hostname}". Please register it first at POST /api/domains/register.`,
      });
    }

    if (!domainRecord.is_verified) {
      return res.status(403).json({
        error: 'Domain not verified.',
        message: `You must verify ownership of "${hostname}" before scanning. Use one of the verification methods: DNS (POST /api/domains/verify/dns), File (POST /api/domains/verify/file), or Meta Tag (POST /api/domains/verify/meta).`,
      });
    }

    // ── Plan-based scan limit enforcement ──────────────────────
    const { data: userRecord, error: userError } = await supabase
      .from('users')
      .select('plan')
      .eq('id', userId)
      .single();

    if (userError) throw userError;

    const userPlan = userRecord?.plan || 'free';

    if (userPlan === 'free') {
      const FREE_MONTHLY_LIMIT = 10;

      // Calculate start of current calendar month in UTC
      const now = new Date();
      const monthStart = new Date(Date.UTC(now.getFullYear(), now.getMonth(), 1)).toISOString();

      const { count: monthlyScans, error: countError } = await supabase
        .from('scans')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', userId)
        .gte('created_at', monthStart);

      if (countError) throw countError;

      if (monthlyScans >= FREE_MONTHLY_LIMIT) {
        return res.status(403).json({
          error: 'Monthly scan limit reached. Upgrade to Pro for unlimited scans.',
          scansUsed: monthlyScans,
          scansLimit: FREE_MONTHLY_LIMIT,
          plan: 'free'
        });
      }
    }

    // Domain is verified & quota OK — run the full scan
    const report = await runFullScan(url, domainRecord.id, userId);

    return res.status(200).json(report);
  } catch (err) {
    next(err);
  }
};

// ─── GET /api/scan/history ────────────────────────────────────
exports.getScanHistory = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { domain, page } = req.query;

    console.log('[ScanHistory] Fetching for user:', userId, '| page:', page, '| domain filter:', domain || 'none');

    const pageNum = Math.max(parseInt(page) || 1, 1);
    const perPage = 20;
    const from = (pageNum - 1) * perPage;
    const to = from + perPage - 1;

    // Build query — select top-level columns (no need to parse the JSONB blob)
    let query = supabase
      .from('scans')
      .select('id, domain_id, scanned_url, total_findings, risk_score, created_at, domains(domain)', { count: 'exact' })
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .range(from, to);

    // Optional domain filter — join through the domains table
    if (domain) {
      // First resolve the domain_id for this user
      const { data: domainRecord } = await supabase
        .from('domains')
        .select('id')
        .eq('user_id', userId)
        .eq('domain', domain)
        .maybeSingle();

      if (!domainRecord) {
        return res.status(404).json({ error: `Domain "${domain}" not found in your account.` });
      }

      query = query.eq('domain_id', domainRecord.id);
    }

    const { data: scans, error, count } = await query;

    if (error) {
      console.error('[ScanHistory] Supabase error:', error.message);
      throw error;
    }

    console.log(`[ScanHistory] Found ${scans?.length || 0} scans (total: ${count})`);

    return res.status(200).json({
      scans: scans || [],
      pagination: {
        page: pageNum,
        per_page: perPage,
        total: count,
        total_pages: Math.ceil(count / perPage),
      },
    });
  } catch (err) {
    next(err);
  }
};

// ─── GET /api/scan/:id ───────────────────────────────────────
exports.getScanById = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    console.log('[ScanById] Fetching scan:', id, '| user:', userId);

    const { data: scan, error } = await supabase
      .from('scans')
      .select('*, domains(domain)')
      .eq('id', id)
      .eq('user_id', userId)
      .maybeSingle();

    if (error) {
      console.error('[ScanById] Supabase error:', error.message);
      throw error;
    }

    if (!scan) {
      console.log('[ScanById] No scan found for id:', id);
      return res.status(404).json({ error: 'Scan report not found or access denied.' });
    }

    console.log('[ScanById] Found scan, risk_score:', scan.risk_score, '| findings type:', typeof scan.findings);

    return res.status(200).json(scan);
  } catch (err) {
    next(err);
  }
};
