import { COMMON_DOMAINS, LOCAL_BLACKLIST, levenshteinDistance } from './utils.js';

// -----------------------------------------------------------------------------
// --- CONFIGURATION ---
// -----------------------------------------------------------------------------
// ⚠️ PASTE YOUR VIRUSTOTAL API KEY HERE ⚠️
const VT_API_KEY = '33a3b01879c1f07e6308c921dd68b4eb502a64ce68071c3b5ab71c2e1d95a412';
// -----------------------------------------------------------------------------

const apiCache = new Map(); // Cache API results for 15 minutes to avoid rate limits

async function analyzeLink(url) {
  const result = {
    url: url,
    score: 0,
    verdict: 'Safe',
    details: {}
  };

  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {
    result.score += 10;
    result.details.parsingError = 'Invalid URL format.';
    return result; // Can't analyze further
  }

  const host = urlObj.hostname.toLowerCase();
  const domainParts = host.replace(/^www\./, '').split('.');
  const primaryDomain = domainParts.slice(-2).join('.'); // e.g., 'example.co.uk' -> 'co.uk', wrong. Let's fix.
  const effectiveDomain = domainParts.length > 2 ? domainParts.slice(-2).join('.') : host; // A simple way to get "domain.com"

  // 1. Local Blacklist Check (Highest Priority)
  if (LOCAL_BLACKLIST.includes(host)) {
    result.score = 100;
    result.verdict = 'Danger';
    result.details.blacklist = 'Domain is on a local blacklist.';
  }

  // 2. Typosquatting Check
  for (const common of COMMON_DOMAINS) {
    const distance = levenshteinDistance(effectiveDomain, common);
    if (distance > 0 && distance < 3) {
      result.score = Math.max(result.score, 65);
      result.verdict = 'Suspicious';
      result.details.typosquatting = { detected: host, original: common };
      break;
    }
  }

  // 3. Heuristic-based Scoring
  if (host.split('.').length > 4) result.score += 20; // Deep subdomains
  if (/[0-9-]{6,}/.test(host)) result.score += 25; // Many digits/dashes
  if (/login|verify|secure|account|update/i.test(urlObj.pathname)) result.score += 15;
  if (urlObj.protocol === 'http:') result.score += 30; // non-TLS

  // 4. VirusTotal API Check (if not already deemed dangerous)
  if (VT_API_KEY && VT_API_KEY !== 'YOUR_VT_API_KEY_HERE' && result.score < 80) {
    const cached = apiCache.get(host);
    if (cached && (Date.now() - cached.timestamp < 15 * 60 * 1000)) {
      if (cached.data > 0) {
        result.score = Math.max(result.score, 85);
        result.verdict = 'Danger';
        result.details.virustotal = `Detected by ${cached.data} security vendors.`;
      }
    } else {
      try {
        const response = await fetch(`https://www.virustotal.com/api/v3/domains/${host}`, {
          headers: { 'x-apikey': VT_API_KEY }
        });
        if (response.ok) {
          const vtData = await response.json();
          const stats = vtData.data.attributes.last_analysis_stats;
          const maliciousCount = stats.malicious + stats.suspicious;
          apiCache.set(host, { data: maliciousCount, timestamp: Date.now() });
          if (maliciousCount > 0) {
            result.score = Math.max(result.score, 85);
            result.verdict = 'Danger';
            result.details.virustotal = `Detected by ${maliciousCount} security vendors.`;
          }
        }
      } catch (e) {
        console.warn('VirusTotal API call failed:', e);
      }
    }
  }

  // Final Verdict Calculation
  result.score = Math.min(result.score, 100);
  if (result.score >= 80) result.verdict = 'Danger';
  else if (result.score >= 40) result.verdict = 'Suspicious';
  else result.verdict = 'Safe';

  return result;
}

async function processLinks(links) {
  if (!Array.isArray(links)) return [];
  const uniqueLinks = Array.from(new Set(links));
  const analysisPromises = uniqueLinks.map(link => analyzeLink(link));
  const results = await Promise.all(analysisPromises);
  // Filter out safe links to only show what matters to the user
  return results.filter(r => r.score >= 40);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'analyzeLinks') {
    processLinks(msg.links || []).then(results => {
      chrome.runtime.sendMessage({ action: 'analysisResults', results });
    });
    // Return true to indicate we will send a response asynchronously
    return true;
  }
});