const axios = require('axios');

/**
 * Sensitive paths to probe. Each entry describes what the file is
 * and why its exposure is dangerous.
 */
const SENSITIVE_PATHS = [
  {
    path: '/.env',
    description: 'Environment file exposed — may contain database credentials, API keys, and secrets.',
    recommendation: 'Block access to .env via your web server config and never store it in a public directory.',
  },
  {
    path: '/.git/config',
    description: 'Git repository config exposed — attackers can reconstruct your source code and history.',
    recommendation: 'Block access to the .git/ directory via your web server config (e.g. deny all in Nginx/Apache).',
  },
  {
    path: '/wp-config.php',
    description: 'WordPress config file exposed — contains database host, name, username, and password.',
    recommendation: 'Move wp-config.php above the web root or restrict access via server config.',
  },
  {
    path: '/phpinfo.php',
    description: 'phpinfo() output exposed — reveals PHP version, server configuration, and loaded modules.',
    recommendation: 'Delete this file from production. Never leave phpinfo() files on a live server.',
  },
  {
    path: '/.htaccess',
    description: 'Apache .htaccess file exposed — may reveal URL rewrite rules, access restrictions, and directory structure.',
    recommendation: 'Configure Apache to deny access to .htaccess files: <Files ".htaccess"> Require all denied </Files>',
  },
  {
    path: '/admin',
    description: 'Admin panel is publicly accessible — makes it easier for attackers to attempt brute-force login.',
    recommendation: 'Restrict /admin access by IP whitelist, add rate limiting, or move to a non-guessable path.',
  },
  {
    path: '/backup.sql',
    description: 'SQL backup file exposed — gives attackers a full copy of your database.',
    recommendation: 'Remove all backup files from the web root and store them in a private, non-accessible location.',
  },
  {
    path: '/database.sql',
    description: 'SQL dump file exposed — gives attackers a full copy of your database.',
    recommendation: 'Remove all database dump files from the web root immediately.',
  },
  {
    path: '/config.php',
    description: 'Configuration file exposed — may contain database credentials or application secrets.',
    recommendation: 'Move config.php outside the web root or deny access via your server configuration.',
  },
  {
    path: '/server-status',
    description: 'Apache server-status page exposed — reveals active connections, request details, and server internals.',
    recommendation: 'Restrict /server-status to localhost or trusted IPs only in your Apache configuration.',
  },
];

/**
 * Checks a single URL path and returns true if it responds with HTTP 200.
 * Times out after 5 seconds regardless of the global env setting.
 * Extracts a substring of the body for deep inspection.
 */
async function probeUrl(url) {
  try {
    const response = await axios.get(url, {
      timeout: 5000,
      validateStatus: () => true,
      maxRedirects: 3,
      responseType: 'text',
      headers: {
        'User-Agent': 'SiteGuardianBot/1.0 (Security Scanner)',
      },
    });
    const body = typeof response.data === 'string' ? response.data.substring(0, 50000).trim() : '';
    return { status: response.status, body, reachable: true };
  } catch {
    return { status: null, body: '', reachable: false };
  }
}

/**
 * Validates a sensitive file expose finding by inspecting the response body
 * to prevent false positives from CDNs or SPA frameworks (Vercel/Netlify)
 * returning soft-200 404 pages.
 */
function validateFileExposure(path, body) {
  if (!body) return false;
  
  const lowerBody = body.toLowerCase();
  
  // Generic false positive detection (Custom 404 pages mapped to 200)
  if (body.length < 20) return false;
  
  if (path === '/.git/config') {
    return lowerBody.includes('[core]') || lowerBody.includes('repositoryformatversion') || lowerBody.includes('filemode');
  }
  if (path === '/server-status') {
    return lowerBody.includes('apache server status') || lowerBody.includes('server version') || lowerBody.includes('current time');
  }
  if (path === '/phpinfo.php') {
    return lowerBody.includes('php version') || lowerBody.includes('php credits');
  }
  if (path === '/.env') {
    return /(?:DB_|APP_KEY|SECRET|[A-Z_]+)=/i.test(body);
  }
  if (path === '/wp-config.php') {
    return lowerBody.includes('db_name') || lowerBody.includes('db_password') || lowerBody.includes('table_prefix');
  }
  
  // For other generic config/db files, if they match HTML structure it's highly likely a soft 404
  if (lowerBody.includes('<!doctype html') || lowerBody.includes('<html') || lowerBody.includes('<head>')) {
    return false;
  }
  
  // Assume confirmed if it's a binary file or unknown text payload that isn't obviously HTML
  return true;
}

/**
 * Scans a domain for exposed sensitive files and paths.
 *
 * @param {string} domain - bare hostname, e.g. example.com
 * @returns {Promise<{ domain, findings, passed, summary }>}
 */
async function scanExposedFiles(domain) {
  const baseUrl = `https://${domain}`;

  // Run all probes concurrently for speed
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async (entry) => {
      const url = `${baseUrl}${entry.path}`;
      const { status, body, reachable } = await probeUrl(url);
      return { ...entry, url, status, body, reachable };
    })
  );

  const findings = [];
  const passed = [];

  for (const result of results) {
    if (result.reachable && result.status === 200) {
      const isConfirmed = validateFileExposure(result.path, result.body);
      
      findings.push({
        path: result.path,
        url: result.url,
        severity: isConfirmed ? 'critical' : 'unconfirmed',
        fixLevel: 'app',
        status: 'exposed',
        httpStatus: result.status,
        description: isConfirmed 
          ? result.description 
          : `${result.description} (Note: The server returned a 200 OK, but the file contents appear to be a custom 404 page or unexpected format. Manual verification required.)`,
        recommendation: result.recommendation,
      });
    } else {
      passed.push(result.path);
    }
  }

  return {
    domain,
    findings,
    passed,
    summary: {
      total: SENSITIVE_PATHS.length,
      exposed: findings.length,
      safe: passed.length,
      critical: findings.length, // all exposed files are critical
    },
  };
}

module.exports = { scanExposedFiles };
