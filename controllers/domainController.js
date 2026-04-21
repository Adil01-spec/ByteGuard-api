const { v4: uuidv4 } = require('uuid');
const dns = require('dns').promises;
const axios = require('axios');
const supabase = require('../config/supabase');

// ─── POST /api/domains/register ───────────────────────────────
exports.registerDomain = async (req, res, next) => {
  try {
    const { domain } = req.body;
    const userId = req.user.id;

    if (!domain) {
      return res.status(400).json({ error: 'Domain name is required.' });
    }

    // Basic domain format validation
    const domainRegex = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain name format.' });
    }

    // Check if this user already registered this domain
    const { data: existing } = await supabase
      .from('domains')
      .select('id')
      .eq('user_id', userId)
      .eq('domain', domain)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({ error: 'You have already registered this domain.' });
    }

    // Generate unique verification token
    const verificationToken = uuidv4();

    // Insert domain record
    const { data: domainRecord, error } = await supabase
      .from('domains')
      .insert({
        id: uuidv4(),
        user_id: userId,
        domain,
        is_verified: false,
        verification_token: verificationToken,
        verification_method: null,
      })
      .select()
      .single();

    if (error) throw error;

    // Build verification instructions
    const verificationInstructions = {
      dns_txt: {
        method: 'DNS TXT Record',
        description: "Add the following TXT record to your domain's DNS settings.",
        record_name: `_site-guardian-verification.${domain}`,
        record_type: 'TXT',
        record_value: `site-guardian-verification=${verificationToken}`,
        note: 'DNS changes can take up to 48 hours to propagate.',
      },
      file_upload: {
        method: 'File Upload',
        description: 'Upload a file to the root of your website at the path shown below.',
        file_path: `/.well-known/site-guardian-verification.txt`,
        file_url: `http://${domain}/.well-known/site-guardian-verification.txt`,
        file_content: verificationToken,
        note: 'Ensure the file is publicly accessible and returns a 200 status.',
      },
      meta_tag: {
        method: 'HTML Meta Tag',
        description: 'Add the following <meta> tag inside the <head> section of your homepage.',
        meta_tag: `<meta name="site-guardian-verification" content="${verificationToken}" />`,
        note: 'The tag must be present on the root page of your domain.',
      },
    };

    return res.status(201).json({
      domain: domainRecord,
      verification: verificationInstructions,
    });
  } catch (err) {
    next(err);
  }
};

// ─── POST /api/domains/verify/dns ─────────────────────────────
exports.verifyDns = async (req, res, next) => {
  try {
    const { domain } = req.body;
    const userId = req.user.id;

    if (!domain) {
      return res.status(400).json({ error: 'Domain name is required.' });
    }

    // Fetch the domain record belonging to this user
    const { data: domainRecord, error: fetchError } = await supabase
      .from('domains')
      .select('id, verification_token, is_verified')
      .eq('user_id', userId)
      .eq('domain', domain)
      .maybeSingle();

    if (fetchError) throw fetchError;

    if (!domainRecord) {
      return res.status(404).json({ error: 'Domain not found. Please register it first.' });
    }

    if (domainRecord.is_verified) {
      return res.status(200).json({
        verified: true,
        message: 'Domain is already verified.',
      });
    }

    const expectedToken = `site-guardian-verification=${domainRecord.verification_token}`;
    const txtHostname = `_site-guardian-verification.${domain}`;

    // Resolve TXT records from live DNS
    let txtRecords;
    try {
      txtRecords = await dns.resolveTxt(txtHostname);
    } catch (dnsErr) {
      // ENODATA / ENOTFOUND — no TXT records found yet
      return res.status(200).json({
        verified: false,
        message: `No TXT records found for "${txtHostname}". Make sure the record is added and DNS has propagated (can take up to 48h).`,
        expected_record: expectedToken,
      });
    }

    // resolveTxt returns string[][] — flatten to a single string[]
    const allValues = txtRecords.flat();
    const found = allValues.some((v) => v === expectedToken);

    if (!found) {
      return res.status(200).json({
        verified: false,
        message: 'TXT record exists but the verification token was not found. Double-check the record value.',
        expected_record: expectedToken,
        found_records: allValues,
      });
    }

    // Token matched — update domain as verified
    const { data: updated, error: updateError } = await supabase
      .from('domains')
      .update({ is_verified: true, verification_method: 'dns' })
      .eq('id', domainRecord.id)
      .select()
      .single();

    if (updateError) throw updateError;

    return res.status(200).json({
      verified: true,
      message: 'Domain verified successfully via DNS TXT record.',
      domain: updated,
    });
  } catch (err) {
    next(err);
  }
};

// ─── POST /api/domains/verify/file ────────────────────────────
exports.verifyFile = async (req, res, next) => {
  try {
    const { domain } = req.body;
    const userId = req.user.id;

    if (!domain) {
      return res.status(400).json({ error: 'Domain name is required.' });
    }

    // Fetch the domain record belonging to this user
    const { data: domainRecord, error: fetchError } = await supabase
      .from('domains')
      .select('id, verification_token, is_verified')
      .eq('user_id', userId)
      .eq('domain', domain)
      .maybeSingle();

    if (fetchError) throw fetchError;

    if (!domainRecord) {
      return res.status(404).json({ error: 'Domain not found. Please register it first.' });
    }

    if (domainRecord.is_verified) {
      return res.status(200).json({
        verified: true,
        message: 'Domain is already verified.',
      });
    }

    const token = domainRecord.verification_token;
    const fileUrl = `https://${domain}/site-guardian-${token}.txt`;

    // Attempt to fetch the verification file
    let fileContent;
    try {
      const response = await axios.get(fileUrl, {
        timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
        validateStatus: () => true, // handle all HTTP statuses manually
        responseType: 'text',
      });

      if (response.status !== 200) {
        return res.status(200).json({
          verified: false,
          message: `File not found at ${fileUrl}. Server responded with HTTP ${response.status}.`,
          expected_url: fileUrl,
          expected_content: token,
        });
      }

      fileContent = response.data.trim();
    } catch (axiosErr) {
      // Domain unreachable, timeout, ENOTFOUND, etc.
      const reason =
        axiosErr.code === 'ECONNABORTED'
          ? 'Request timed out — the domain may be too slow or unreachable.'
          : axiosErr.code
          ? `Network error (${axiosErr.code}) — ensure the domain is publicly accessible over HTTPS.`
          : 'Could not reach the domain. Ensure it is live and publicly accessible.';

      return res.status(200).json({
        verified: false,
        message: reason,
        expected_url: fileUrl,
        expected_content: token,
      });
    }

    // Compare trimmed file content against the raw token
    if (fileContent !== token) {
      return res.status(200).json({
        verified: false,
        message: 'File found but its content does not match the verification token.',
        expected_content: token,
        found_content: fileContent,
      });
    }

    // Token matched — mark domain as verified
    const { data: updated, error: updateError } = await supabase
      .from('domains')
      .update({ is_verified: true, verification_method: 'file' })
      .eq('id', domainRecord.id)
      .select()
      .single();

    if (updateError) throw updateError;

    return res.status(200).json({
      verified: true,
      message: 'Domain verified successfully via file upload.',
      domain: updated,
    });
  } catch (err) {
    next(err);
  }
};

// ─── POST /api/domains/verify/meta ────────────────────────────
exports.verifyMeta = async (req, res, next) => {
  try {
    const { domain } = req.body;
    const userId = req.user.id;

    if (!domain) {
      return res.status(400).json({ error: 'Domain name is required.' });
    }

    // Fetch domain record belonging to this user
    const { data: domainRecord, error: fetchError } = await supabase
      .from('domains')
      .select('id, verification_token, is_verified')
      .eq('user_id', userId)
      .eq('domain', domain)
      .maybeSingle();

    if (fetchError) throw fetchError;

    if (!domainRecord) {
      return res.status(404).json({ error: 'Domain not found. Please register it first.' });
    }

    if (domainRecord.is_verified) {
      return res.status(200).json({
        verified: true,
        message: 'Domain is already verified.',
      });
    }

    const token = domainRecord.verification_token;
    const homepageUrl = `https://${domain}`;

    // Fetch the homepage HTML
    let html;
    try {
      const response = await axios.get(homepageUrl, {
        timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
        validateStatus: () => true,
        responseType: 'text',
        headers: {
          'User-Agent': 'SiteGuardianBot/1.0 (Domain Verification)',
        },
      });

      if (response.status !== 200) {
        return res.status(200).json({
          verified: false,
          message: `Homepage returned HTTP ${response.status}. Ensure the domain is live and accessible.`,
          expected_meta_tag: `<meta name="site-guardian-verify" content="${token}" />`,
        });
      }

      html = response.data;
    } catch (axiosErr) {
      const reason =
        axiosErr.code === 'ECONNABORTED'
          ? 'Request timed out — the domain may be too slow or unreachable.'
          : axiosErr.code
          ? `Network error (${axiosErr.code}) — ensure the domain is publicly accessible over HTTPS.`
          : 'Could not reach the domain. Ensure it is live and publicly accessible.';

      return res.status(200).json({
        verified: false,
        message: reason,
        expected_meta_tag: `<meta name="site-guardian-verify" content="${token}" />`,
      });
    }

    // Parse HTML and locate the verification meta tag
    const cheerio = require('cheerio');
    const $ = cheerio.load(html);
    const metaContent = $('meta[name="site-guardian-verify"]').attr('content');

    if (!metaContent) {
      return res.status(200).json({
        verified: false,
        message: 'Verification meta tag not found on the homepage <head>.',
        expected_meta_tag: `<meta name="site-guardian-verify" content="${token}" />`,
      });
    }

    if (metaContent.trim() !== token) {
      return res.status(200).json({
        verified: false,
        message: 'Meta tag found but its content does not match the verification token.',
        expected_content: token,
        found_content: metaContent.trim(),
      });
    }

    // Token matched — update domain as verified
    const { data: updated, error: updateError } = await supabase
      .from('domains')
      .update({ is_verified: true, verification_method: 'meta' })
      .eq('id', domainRecord.id)
      .select()
      .single();

    if (updateError) throw updateError;

    return res.status(200).json({
      verified: true,
      message: 'Domain verified successfully via HTML meta tag.',
      domain: updated,
    });
  } catch (err) {
    next(err);
  }
};

// ─── GET /api/domains ─────────────────────────────────────────
exports.getDomains = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { data: domains, error } = await supabase
      .from('domains')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    
    return res.status(200).json(domains);
  } catch (err) {
    next(err);
  }
};

// ─── DELETE /api/domains/:id ──────────────────────────────
exports.deleteDomain = async (req, res, next) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    if (!id) {
      return res.status(400).json({ error: 'Domain ID is required.' });
    }

    // Verify ownership
    const { data: domain, error: fetchError } = await supabase
      .from('domains')
      .select('id, user_id')
      .eq('id', id)
      .single();

    if (fetchError || !domain) {
      return res.status(404).json({ error: 'Domain not found.' });
    }

    if (domain.user_id !== userId) {
      return res.status(403).json({ error: 'Unauthorized to delete this domain.' });
    }

    // Perform manual deletion of related records in case cascade isn't set up yet
    await supabase.from('notifications').delete().eq('domain_id', id);
    await supabase.from('scans').delete().eq('domain_id', id);

    // Delete domain
    const { error: deleteError } = await supabase
      .from('domains')
      .delete()
      .eq('id', id);

    if (deleteError) {
      console.error('[Domain Delete Error]', deleteError);
      return res.status(500).json({ error: 'Failed to delete domain.' });
    }

    return res.status(200).json({ message: 'Domain deleted successfully.' });
  } catch (err) {
    next(err);
  }
};
