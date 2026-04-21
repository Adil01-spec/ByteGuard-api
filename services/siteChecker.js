// services/siteChecker.js
// Core site-checking logic: uptime, SSL, DNS, metadata scraping

const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const sslChecker = require('ssl-checker');

/**
 * Check if a site is reachable and measure response time.
 */
async function checkUptime(url) {
  const start = Date.now();
  const response = await axios.get(url, {
    timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
  });
  return {
    status: response.status,
    responseTimeMs: Date.now() - start,
  };
}

/**
 * Check SSL certificate details for a hostname.
 */
async function checkSSL(hostname) {
  const result = await sslChecker(hostname);
  return result;
}

/**
 * Resolve DNS records for a hostname.
 */
async function checkDNS(hostname) {
  const [a, mx] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolveMx(hostname),
  ]);
  return {
    a: a.status === 'fulfilled' ? a.value : null,
    mx: mx.status === 'fulfilled' ? mx.value : null,
  };
}

/**
 * Scrape basic metadata (title, description) from a URL.
 */
async function scrapeMetadata(url) {
  const { data } = await axios.get(url, {
    timeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 10000,
  });
  const $ = cheerio.load(data);
  return {
    title: $('title').text(),
    description: $('meta[name="description"]').attr('content') || null,
  };
}

module.exports = { checkUptime, checkSSL, checkDNS, scrapeMetadata };
