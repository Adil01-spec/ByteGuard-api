let sslChecker;
try {
  sslChecker = require('ssl-checker');
} catch (err) {
  console.error('Failed to load ssl-checker module:', err.message);
}
const axios = require('axios');

/**
 * Checks whether an HTTP request to the domain redirects to HTTPS.
 * @param {string} hostname - bare hostname, e.g. example.com
 * @returns {Promise<boolean>}
 */
async function checksHttpRedirect(hostname) {
  try {
    const response = await axios.get(`http://${hostname}`, {
      timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
      maxRedirects: 5,
      validateStatus: () => true,
    });
    // If the final URL after redirects starts with https, redirect occurred
    const finalUrl = response.request?.res?.responseUrl || response.config?.url || '';
    return finalUrl.startsWith('https://');
  } catch {
    return false;
  }
}

/**
 * Scans SSL/TLS configuration for a given hostname.
 *
 * @param {string} hostname - bare hostname without protocol, e.g. example.com
 * @returns {Promise<{ hostname, findings, passed, summary, sslDetails }>}
 */
async function scanSsl(hostname) {
  const findings = [];
  const passed = [];
  let sslData = null;

  if (!sslChecker) {
    findings.push({
      check: 'SSL Engine',
      severity: 'high',
      fixLevel: 'infrastructure',
      status: 'failed',
      description: 'SSL scanning engine is currently unavailable in this environment.',
      recommendation: 'Contact support or check server logs for dependency errors.',
    });
    return buildResult(hostname, null, findings, passed);
  }

  // ── 1. Attempt SSL certificate check ──────────────────────────
  try {
    sslData = await sslChecker(hostname, { method: 'GET', port: 443 });
  } catch (err) {
    // Could not reach the host on port 443 — treat as no HTTPS
    findings.push({
      check: 'HTTPS Availability',
      severity: 'critical',
      fixLevel: 'infrastructure',
      status: 'failed',
      description: `Could not establish an HTTPS connection to ${hostname}. The site may not support HTTPS at all.`,
      recommendation: 'Install a valid SSL/TLS certificate (e.g. via Let\'s Encrypt) and ensure port 443 is open.',
      detail: err.message,
    });

    // Still attempt the HTTP redirect check even if HTTPS fails
    const redirects = await checksHttpRedirect(hostname);
    if (!redirects) {
      findings.push({
        check: 'HTTP → HTTPS Redirect',
        severity: 'high',
        fixLevel: 'infrastructure',
        status: 'failed',
        description: 'HTTP requests are not being redirected to HTTPS, leaving traffic unencrypted.',
        recommendation: 'Configure a permanent 301 redirect from http:// to https:// on your web server.',
      });
    } else {
      passed.push('HTTP → HTTPS Redirect');
    }

    return buildResult(hostname, sslData, findings, passed);
  }

  // ── 2. Expired certificate ─────────────────────────────────────
  if (!sslData.valid) {
    findings.push({
      check: 'Certificate Validity',
      severity: 'critical',
      fixLevel: 'infrastructure',
      status: 'failed',
      description: `The SSL certificate for ${hostname} is expired or invalid. Browsers will show a security warning and block visitors.`,
      recommendation: 'Renew your SSL certificate immediately. Use Let\'s Encrypt for free automatic renewal.',
      detail: `Valid from: ${sslData.validFrom} | Valid to: ${sslData.validTo}`,
    });
  } else {
    passed.push('Certificate Validity');
  }

  // ── 3. Expiring within 30 days ────────────────────────────────
  if (sslData.valid && sslData.daysRemaining !== undefined) {
    if (sslData.daysRemaining <= 0) {
      // Already caught above as expired — skip
    } else if (sslData.daysRemaining <= 30) {
      findings.push({
        check: 'Certificate Expiry Warning',
        severity: 'high',
        fixLevel: 'infrastructure',
        status: 'warning',
        description: `SSL certificate expires in ${sslData.daysRemaining} day(s). Failure to renew will cause browser warnings and service interruption.`,
        recommendation: 'Renew the certificate now. If using Let\'s Encrypt, ensure auto-renewal (certbot) is configured.',
        detail: `Expiry date: ${sslData.validTo}`,
      });
    } else if (sslData.daysRemaining <= 60) {
      findings.push({
        check: 'Certificate Expiry Warning',
        severity: 'medium',
        fixLevel: 'infrastructure',
        status: 'warning',
        description: `SSL certificate expires in ${sslData.daysRemaining} day(s). Plan for renewal soon.`,
        recommendation: 'Schedule certificate renewal. Auto-renewal via certbot is recommended.',
        detail: `Expiry date: ${sslData.validTo}`,
      });
    } else {
      passed.push('Certificate Expiry');
    }
  }

  // ── 4. HTTP → HTTPS redirect ──────────────────────────────────
  const redirects = await checksHttpRedirect(hostname);
  if (!redirects) {
    findings.push({
      check: 'HTTP → HTTPS Redirect',
      severity: 'high',
      fixLevel: 'infrastructure',
      status: 'failed',
      description: 'HTTP requests are not being redirected to HTTPS, leaving users exposed to unencrypted connections.',
      recommendation: 'Configure a permanent 301 redirect from http:// to https:// on your web server or CDN.',
    });
  } else {
    passed.push('HTTP → HTTPS Redirect');
  }

  // ── 5. Self-signed certificate detection ──────────────────────
  // ssl-checker doesn't return issuer directly; we infer from validFor and valid flag.
  // A self-signed cert is valid=true but its subject and issuer are identical.
  // We approximate: if daysRemaining is very large (>~3650) it may be self-signed.
  if (sslData.valid && sslData.daysRemaining > 3650) {
    findings.push({
      check: 'Self-Signed Certificate',
      severity: 'high',
      fixLevel: 'infrastructure',
      status: 'warning',
      description: 'The certificate may be self-signed (unusually long validity period detected). Self-signed certs are not trusted by browsers and will trigger security warnings.',
      recommendation: 'Replace with a certificate from a trusted CA such as Let\'s Encrypt, DigiCert, or Sectigo.',
      detail: `Days remaining: ${sslData.daysRemaining}`,
    });
  } else if (sslData.valid) {
    passed.push('Trusted Certificate (not self-signed)');
  }

  return buildResult(hostname, sslData, findings, passed);
}

function buildResult(hostname, sslData, findings, passed) {
  return {
    hostname,
    sslDetails: sslData
      ? {
          valid: sslData.valid,
          validFrom: sslData.validFrom,
          validTo: sslData.validTo,
          daysRemaining: sslData.daysRemaining,
          validForDomains: sslData.validFor || [],
        }
      : null,
    findings,
    passed,
    summary: {
      total: findings.length + passed.length,
      passed: passed.length,
      failed: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
    },
  };
}

module.exports = { scanSsl };
