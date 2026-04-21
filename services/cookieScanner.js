const axios = require('axios');

/**
 * Parses a raw Set-Cookie header string and extracts:
 * - name, value, and all directive flags.
 */
function parseCookie(rawCookie) {
  const parts = rawCookie.split(';').map((p) => p.trim());
  const [nameValue, ...directives] = parts;

  const eqIndex = nameValue.indexOf('=');
  const name = eqIndex !== -1 ? nameValue.substring(0, eqIndex).trim() : nameValue.trim();
  const value = eqIndex !== -1 ? nameValue.substring(eqIndex + 1).trim() : '';

  const directiveStr = directives.join(';').toLowerCase();

  return {
    name,
    value,
    raw: rawCookie,
    hasHttpOnly: directiveStr.includes('httponly'),
    hasSecure: directiveStr.includes('secure'),
    hasSameSite: directiveStr.includes('samesite'),
    sameSiteValue: (() => {
      const match = directiveStr.match(/samesite=(\w+)/);
      return match ? match[1] : null;
    })(),
  };
}

/**
 * Scans all cookies set by a URL for missing security attributes.
 *
 * @param {string} url - Full URL to fetch, e.g. https://example.com
 * @returns {Promise<{ scannedUrl, cookiesFound, findings, passed, summary }>}
 */
async function scanCookies(url) {
  const response = await axios.get(url, {
    timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
    validateStatus: () => true,
    maxRedirects: 5,
    headers: {
      'User-Agent': 'SiteGuardianBot/1.0 (Cookie Security Scanner)',
    },
  });

  // axios normalises headers; Set-Cookie may be an array or a single string
  const rawSetCookie = response.headers['set-cookie'];

  if (!rawSetCookie || rawSetCookie.length === 0) {
    return {
      scannedUrl: url,
      cookiesFound: 0,
      findings: [],
      passed: [],
      summary: { total: 0, passed: 0, failed: 0, medium: 0 },
      note: 'No Set-Cookie headers were found in the response.',
    };
  }

  const cookieList = Array.isArray(rawSetCookie) ? rawSetCookie : [rawSetCookie];
  const findings = [];
  const passed = [];

  const INFRASTRUCTURE_COOKIES = [
    '__cf_bm', '__cfduid', '__utma', '__utmb', '__utmc', '__utmz', '_ga', '_gid', '_fbp'
  ];

  for (const raw of cookieList) {
    const cookie = parseCookie(raw);
    let hasFinding = false;
    const isInfra = INFRASTRUCTURE_COOKIES.includes(cookie.name);
    const fixLevel = isInfra ? 'infrastructure' : 'app';
    const severityOverride = isInfra ? 'informational' : 'medium';
    
    // ── HttpOnly ──────────────────────────────────────────────
    if (!cookie.hasHttpOnly) {
      findings.push({
        cookie: cookie.name,
        attribute: 'HttpOnly',
        severity: severityOverride,
        fixLevel,
        status: 'missing',
        description: `Cookie "${cookie.name}" is missing the HttpOnly flag. It can be read by JavaScript, making it vulnerable to XSS-based session theft.`,
        recommendation: isInfra ? `This cookie is managed by a third-party service (like Cloudflare or Analytics) and its attributes cannot be controlled from your application code.` : `Set the HttpOnly flag: Set-Cookie: ${cookie.name}=...; HttpOnly`,
      });
      hasFinding = true;
    }

    // ── Secure ────────────────────────────────────────────────
    if (!cookie.hasSecure) {
      findings.push({
        cookie: cookie.name,
        attribute: 'Secure',
        severity: severityOverride,
        fixLevel,
        status: 'missing',
        description: `Cookie "${cookie.name}" is missing the Secure flag. It can be transmitted over unencrypted HTTP connections.`,
        recommendation: isInfra ? `This cookie is managed by a third-party service (like Cloudflare or Analytics) and its attributes cannot be controlled from your application code.` : `Set the Secure flag: Set-Cookie: ${cookie.name}=...; Secure`,
      });
      hasFinding = true;
    }

    // ── SameSite ──────────────────────────────────────────────
    if (!cookie.hasSameSite) {
      findings.push({
        cookie: cookie.name,
        attribute: 'SameSite',
        severity: severityOverride,
        fixLevel,
        status: 'missing',
        description: `Cookie "${cookie.name}" is missing the SameSite attribute. It may be sent with cross-site requests, enabling CSRF attacks.`,
        recommendation: isInfra ? `This cookie is managed by a third-party service (like Cloudflare or Analytics) and its attributes cannot be controlled from your application code.` : `Set SameSite: Set-Cookie: ${cookie.name}=...; SameSite=Strict  (or Lax for broader compatibility)`,
      });
      hasFinding = true;
    }

    if (!hasFinding) {
      passed.push(cookie.name);
    }
  }

  return {
    scannedUrl: url,
    cookiesFound: cookieList.length,
    findings,
    passed,
    summary: {
      total: cookieList.length,
      passed: passed.length,
      failed: cookieList.length - passed.length,
      medium: findings.length,
    },
  };
}

module.exports = { scanCookies };
