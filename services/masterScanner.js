const { v4: uuidv4 } = require('uuid');
const supabase = require('../config/supabase');

const { scanHeaders } = require('./headerScanner');
const { scanSsl } = require('./sslScanner');
const { scanExposedFiles } = require('./exposedFilesScanner');
const { scanCookies } = require('./cookieScanner');
const { scanInfoLeaks } = require('./infoLeakScanner');
const { createNotification } = require('../utils/notification');

/**
 * Extracts the bare hostname from a URL string.
 * e.g. "https://example.com/path" → "example.com"
 */
function extractHostname(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return u.hostname;
  } catch {
    return url;
  }
}

/**
 * Returns the highest severity from a list of findings.
 * Priority: critical > high > medium > low > none
 */
function calculateRiskScore(findings) {
  const severities = findings.map((f) => f.severity);
  if (severities.includes('critical')) return 'critical';
  if (severities.includes('high')) return 'high';
  if (severities.includes('medium')) return 'medium';
  if (severities.includes('low')) return 'low';
  return 'none';
}

/**
 * Runs all 5 scanners in parallel against a URL and returns a combined report.
 * Saves the report to the Supabase `scans` table.
 *
 * @param {string} url       - Target URL (e.g. https://example.com)
 * @param {string} domainId  - UUID of the domain record in the domains table
 * @param {string} userId    - UUID of the authenticated user
 * @returns {Promise<Object>} - Full scan report
 */
async function runFullScan(url, domainId, userId) {
  const fullUrl = url.startsWith('http') ? url : `https://${url}`;
  const hostname = extractHostname(fullUrl);
  const timestamp = new Date().toISOString();

  // Run all 5 scanners concurrently
  const [headerResult, sslResult, exposedResult, cookieResult, infoLeakResult] =
    await Promise.allSettled([
      scanHeaders(fullUrl),
      scanSsl(hostname),
      scanExposedFiles(hostname),
      scanCookies(fullUrl),
      scanInfoLeaks(fullUrl),
    ]);

  // Safely extract findings from each scanner (handle failures gracefully)
  const scanResults = {
    headers: headerResult.status === 'fulfilled' ? headerResult.value : { findings: [], error: headerResult.reason?.message },
    ssl: sslResult.status === 'fulfilled' ? sslResult.value : { findings: [], error: sslResult.reason?.message },
    exposedFiles: exposedResult.status === 'fulfilled' ? exposedResult.value : { findings: [], error: exposedResult.reason?.message },
    cookies: cookieResult.status === 'fulfilled' ? cookieResult.value : { findings: [], error: cookieResult.reason?.message },
    infoLeaks: infoLeakResult.status === 'fulfilled' ? infoLeakResult.value : { findings: [], error: infoLeakResult.reason?.message },
  };

  // Combine all findings into a single array, tagging each with its scanner source
  const allFindings = [
    ...(scanResults.headers.findings || []).map((f) => ({ ...f, scanner: 'headers' })),
    ...(scanResults.ssl.findings || []).map((f) => ({ ...f, scanner: 'ssl' })),
    ...(scanResults.exposedFiles.findings || []).map((f) => ({ ...f, scanner: 'exposed_files' })),
    ...(scanResults.cookies.findings || []).map((f) => ({ ...f, scanner: 'cookies' })),
    ...(scanResults.infoLeaks.findings || []).map((f) => ({ ...f, scanner: 'info_leaks' })),
  ];

  const riskScore = calculateRiskScore(allFindings);

  // Build the complete report
  const report = {
    scanned_url: fullUrl,
    hostname,
    timestamp,
    risk_score: riskScore,
    total_findings: allFindings.length,
    breakdown: {
      critical: allFindings.filter((f) => f.severity === 'critical').length,
      high: allFindings.filter((f) => f.severity === 'high').length,
      medium: allFindings.filter((f) => f.severity === 'medium').length,
      low: allFindings.filter((f) => f.severity === 'low').length,
    },
    findings: allFindings,
    scannerDetails: scanResults,
  };

  // Save the report to the Supabase scans table
  const insertPayload = {
    id: uuidv4(),
    domain_id: domainId,
    user_id: userId,
    scanned_url: fullUrl,
    findings: report,
    risk_score: riskScore,
    total_findings: allFindings.length,
  };

  console.log('[MasterScanner] Saving scan to Supabase:', {
    id: insertPayload.id,
    domain_id: insertPayload.domain_id,
    user_id: insertPayload.user_id,
    risk_score: insertPayload.risk_score,
    total_findings: report.total_findings,
  });

  const { data: scanRecord, error } = await supabase
    .from('scans')
    .insert(insertPayload)
    .select()
    .single();

  if (error) {
    console.error('[MasterScanner] Failed to save scan to Supabase:', error.message, error.details, error.hint);
    // Still return a report but flag it as unsaved
    report.saved = false;
    report.saveError = error.message;
  } else {
    console.log('[MasterScanner] Scan saved successfully with id:', scanRecord.id);
    report.saved = true;
    report.scan_id = scanRecord.id;
  }

  // Notify user if critical or high findings were detected
  const criticalCount = report.breakdown.critical;
  const highCount = report.breakdown.high;

  let savedNotifId = null;
  if (criticalCount > 0 || highCount > 0) {
    const parts = [];
    if (criticalCount > 0) parts.push(`${criticalCount} critical`);
    if (highCount > 0) parts.push(`${highCount} high`);

    const message = `⚠️ Security scan for ${hostname} found ${parts.join(' and ')} severity issue(s). Review your scan results immediately.`;
    // If createNotification returns an ID, we'd use it; otherwise just create it.
    await createNotification(userId, message);
    
    // Attempt to grab the latest notification id to attach to push payload
    const { data: latestNotif } = await supabase
      .from('notifications')
      .select('id')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
      
    if (latestNotif) savedNotifId = latestNotif.id;
  }

  // ---- PUSH NOTIFICATIONS ----
  try {
    const { data: userSubscriptions } = await supabase
      .from('push_subscriptions')
      .select('id, subscription')
      .eq('user_id', userId);

    if (userSubscriptions && userSubscriptions.length > 0) {
      const { sendScanCompleteNotification, sendCriticalAlertNotification } = require('./pushService');
      
      const pScanData = {
        id: report.scan_id,
        domain: hostname,
        risk_score: report.risk_score,
        issues_count: report.total_findings
      };

      await sendScanCompleteNotification(userSubscriptions, pScanData, savedNotifId);

      if (report.risk_score === 'critical') {
        // Send a push for each critical finding
        const criticalFindings = report.findings.filter(f => f.severity === 'critical');
        for (const finding of criticalFindings) {
          await sendCriticalAlertNotification(userSubscriptions, finding, report.scan_id, savedNotifId);
        }
      }
    }
  } catch (pushErr) {
    console.error('[MasterScanner] Failed to process push notifications:', pushErr);
  }

  return report;
}

module.exports = { runFullScan };
