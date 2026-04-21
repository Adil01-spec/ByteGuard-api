const axios = require('axios');

/**
 * Headers that leak server/technology information when present.
 */
const LEAKY_HEADERS = [
  {
    name: 'server',
    label: 'Server',
    description: 'The Server header reveals web server software and version, helping attackers target known vulnerabilities.',
    recommendation: 'Remove or genericise the Server header (e.g. set it to just "webserver") in your web server config.',
  },
  {
    name: 'x-powered-by',
    label: 'X-Powered-By',
    description: 'The X-Powered-By header exposes the technology stack (e.g. Express, PHP, ASP.NET), narrowing the attack surface for an attacker.',
    recommendation: 'Remove the X-Powered-By header. In Express use: app.disable("x-powered-by")',
  },
  {
    name: 'x-aspnet-version',
    label: 'X-AspNet-Version',
    description: 'Exposes the exact ASP.NET framework version, allowing targeted attacks against known vulnerabilities.',
    recommendation: 'Disable in web.config: <httpRuntime enableVersionHeader="false" />',
  },
  {
    name: 'x-aspnetmvc-version',
    label: 'X-AspNetMvc-Version',
    description: 'Exposes the ASP.NET MVC version, providing attackers with framework-specific attack vectors.',
    recommendation: 'Remove in Application_Start: MvcHandler.DisableMvcResponseHeader = true;',
  },
];

/**
 * Patterns that indicate error messages or stack traces in the HTML body.
 * Each regex is tested against the first 100KB of the response body.
 */
const ERROR_PATTERNS = [
  {
    pattern: /fatal\s+error/i,
    label: 'Fatal Error Message',
    description: 'A "Fatal error" message was found in the page. This can reveal file paths, function names, and internal logic.',
  },
  {
    pattern: /stack\s*trace/i,
    label: 'Stack Trace Detected',
    description: 'A stack trace was found in the page, exposing internal code structure, file paths, and line numbers.',
  },
  {
    pattern: /at\s+[\w.]+\s+\(.*:\d+:\d+\)/,
    label: 'JavaScript/Node.js Stack Trace',
    description: 'A Node.js-style stack trace was found, revealing internal file paths and code structure.',
  },
  {
    pattern: /Exception\s+in\s+thread/i,
    label: 'Java Exception',
    description: 'A Java exception trace was found, exposing class names, methods, and server internals.',
  },
  {
    pattern: /Traceback\s+\(most\s+recent\s+call\s+last\)/i,
    label: 'Python Traceback',
    description: 'A Python traceback was found, revealing file paths, function names, and framework details.',
  },
  {
    pattern: /Warning:\s+\w+\(\)/i,
    label: 'PHP Warning',
    description: 'A PHP warning was found, potentially revealing file paths and function names.',
  },
  {
    pattern: /mysql_connect|mysqli_|pg_connect|ORA-\d{5}/i,
    label: 'Database Error / Connection String',
    description: 'A database error or connection reference was found, potentially exposing database type, host, or credentials.',
  },
  {
    pattern: /SQLSTATE\[/i,
    label: 'SQL State Error',
    description: 'A PDO/SQL state error was found, revealing database driver and query details.',
  },
  {
    pattern: /\/home\/\w+\/|\/var\/www\/|C:\\inetpub\\|C:\\Users\\/i,
    label: 'Server File Path Exposed',
    description: 'An absolute server file path was found in the response, revealing the directory structure.',
  },
];

/**
 * Scans a URL for information leakage via headers and response body.
 *
 * @param {string} url - Full URL to scan, e.g. https://example.com
 * @returns {Promise<{ scannedUrl, findings, passed, summary }>}
 */
async function scanInfoLeaks(url) {
  const response = await axios.get(url, {
    timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
    validateStatus: () => true,
    maxRedirects: 5,
    responseType: 'text',
    headers: {
      'User-Agent': 'SiteGuardianBot/1.0 (Info Leak Scanner)',
    },
  });

  const headers = response.headers;
  const body = typeof response.data === 'string' ? response.data.substring(0, 100000) : '';

  const findings = [];
  const passed = [];

  // ── Header checks ──────────────────────────────────────────
  for (const hdr of LEAKY_HEADERS) {
    const value = headers[hdr.name];
    if (value) {
      findings.push({
        check: hdr.label,
        type: 'header',
        severity: 'medium',
        fixLevel: hdr.label === 'Server' ? 'infrastructure' : 'app',
        status: 'exposed',
        headerValue: value,
        description: hdr.description,
        recommendation: hdr.recommendation,
      });
    } else {
      passed.push(hdr.label);
    }
  }

  // ── Body / error message checks ────────────────────────────
  for (const ep of ERROR_PATTERNS) {
    const match = body.match(ep.pattern);
    if (match) {
      findings.push({
        check: ep.label,
        type: 'body',
        severity: 'medium',
        fixLevel: 'app',
        status: 'detected',
        matchedSnippet: match[0].substring(0, 120),
        description: ep.description,
        recommendation: 'Configure your application to hide error details in production. Use custom error pages instead.',
      });
    }
  }

  return {
    scannedUrl: url,
    findings,
    passed,
    summary: {
      total: LEAKY_HEADERS.length + ERROR_PATTERNS.length,
      findings: findings.length,
      headerLeaks: findings.filter((f) => f.type === 'header').length,
      bodyLeaks: findings.filter((f) => f.type === 'body').length,
      medium: findings.length,
    },
  };
}

module.exports = { scanInfoLeaks };
