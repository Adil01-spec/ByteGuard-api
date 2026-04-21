const axios = require('axios');

/**
 * Security header definitions:
 * Each entry defines how to evaluate the header and what to report if missing/weak.
 */
const SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    severity: 'high',
    description:
      'Missing CSP allows attackers to inject malicious scripts (XSS), load external resources, or perform clickjacking.',
    recommendation:
      "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'",
  },
  {
    name: 'Strict-Transport-Security',
    severity: 'high',
    description:
      'Without HSTS, browsers may connect over HTTP, exposing users to man-in-the-middle and SSL-stripping attacks.',
    recommendation:
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
  },
  {
    name: 'X-Frame-Options',
    severity: 'medium',
    description:
      'Without X-Frame-Options, your site can be embedded in iframes, enabling clickjacking attacks.',
    recommendation: 'Add: X-Frame-Options: DENY  (or SAMEORIGIN if you need iframe embedding on your own domain)',
  },
  {
    name: 'X-Content-Type-Options',
    severity: 'medium',
    description:
      'Without this header, browsers may MIME-sniff responses, potentially executing files as unexpected content types.',
    recommendation: 'Add: X-Content-Type-Options: nosniff',
  },
  {
    name: 'X-XSS-Protection',
    severity: 'low',
    description:
      'The X-XSS-Protection header enables the browser\'s built-in XSS filter. While deprecated in modern browsers, older ones benefit from it.',
    recommendation: 'Add: X-XSS-Protection: 1; mode=block',
  },
  {
    name: 'Referrer-Policy',
    severity: 'low',
    description:
      'Without a Referrer-Policy, sensitive URL parameters may be leaked to third-party sites via the Referer header.',
    recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    name: 'Permissions-Policy',
    severity: 'low',
    description:
      'Without a Permissions-Policy, the browser may allow access to powerful APIs (camera, microphone, geolocation) unnecessarily.',
    recommendation:
      'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
  },
];

/**
 * Fetches HTTP response headers for a URL and checks for missing/misconfigured security headers.
 *
 * @param {string} url - The full URL to scan (e.g. https://example.com)
 * @returns {Promise<{ scannedUrl: string, responseStatus: number, findings: Array, passedHeaders: string[] }>}
 */
async function scanHeaders(url) {
  const response = await axios.get(url, {
    timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
    // Resolve for all HTTP status codes so we can still read headers
    validateStatus: () => true,
    // Only follow a limited number of redirects
    maxRedirects: 5,
    headers: {
      'User-Agent': 'SiteGuardianBot/1.0 (Security Header Scanner)',
    },
  });

  const responseHeaders = response.headers;
  const findings = [];
  const passedHeaders = [];

  for (const headerDef of SECURITY_HEADERS) {
    const headerKey = headerDef.name.toLowerCase();
    const value = responseHeaders[headerKey];

    if (!value) {
      findings.push({
        header: headerDef.name,
        severity: headerDef.severity,
        fixLevel: 'app',
        status: 'missing',
        description: headerDef.description,
        recommendation: headerDef.recommendation,
      });
    } else {
      passedHeaders.push(headerDef.name);
    }
  }

  return {
    scannedUrl: url,
    responseStatus: response.status,
    findings,
    passedHeaders,
    summary: {
      total: SECURITY_HEADERS.length,
      passed: passedHeaders.length,
      failed: findings.length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
    },
  };
}

module.exports = { scanHeaders };
