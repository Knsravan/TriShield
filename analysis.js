// background/analysis.js
export function analyzeWithHeuristics(rawUrl) {
    let url = rawUrl;
    try { url = new URL(rawUrl).href; } catch { }

    const reasons = [];
    let risk = 0;

    // Features
    const u = safeParse(url);
    const host = u.hostname || '';
    const path = u.pathname + (u.search || '');
    const full = u.href || rawUrl;

    // Suspicious TLDs & free hosting
    const tlds = ['.zip', '.xyz', '.top', '.buzz', '.quest', '.click', '.country', '.gq', '.tk', '.ml'];
    if (tlds.some(t => host.endsWith(t))) { risk += 0.15; reasons.push('Suspicious TLD'); }

    // IP address host
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) { risk += 0.15; reasons.push('IP address host'); }

    // Excessive subdomains or hyphens
    if (host.split('.').length >= 5) { risk += 0.1; reasons.push('Too many subdomains'); }
    if ((host.match(/-/g) || []).length >= 2) { risk += 0.08; reasons.push('Hyphenated host'); }

    // Homograph / punycode
    if (host.startsWith('xn--')) { risk += 0.12; reasons.push('Punycode host (possible homograph)'); }

    // Phishy keywords
    const kw = ['login', 'signin', 'verify', 'update', 'billing', 'wallet', 'gift', 'giveaway', 'airdrop', 'bonus', 'free', 'password', 'security'];
    if (kw.some(k => path.toLowerCase().includes(k))) { risk += 0.12; reasons.push('Sensitive keyword in path/query'); }

    // Long URL & parameters
    if (full.length > 110) { risk += 0.06; reasons.push('Very long URL'); }
    if ((full.match(/[=&?]/g) || []).length > 8) { risk += 0.06; reasons.push('Many query params'); }

    // Data or javascript URLs
    if (/^(data:|javascript:)/i.test(full)) { risk += 0.3; reasons.push('Data/JS URL'); }

    // Common phishing paths
    const badPaths = ['wp-login.php', 'account/verify', 'steamcommunity', 'id.apple.com', 'service=mail', 'oauth'];
    if (badPaths.some(b => full.toLowerCase().includes(b))) { risk += 0.08; reasons.push('Known-bad style path'); }

    // Clamp
    risk = Math.min(1, risk);
    const verdict = risk >= 0.5 ? 'risk' : 'safe';
    return { score: risk, verdict, reasons };
}

function safeParse(url) { try { return new URL(url); } catch { return { href: url, hostname: '', pathname: '', search: '' }; } }
