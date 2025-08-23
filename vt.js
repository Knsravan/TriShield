// background/vt.js
// Minimal VT flow: POST /urls -> analysis id -> GET /analyses/{id}

export async function vtAnalyze(url, apiKey, timeoutMs = 12000) {
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const submit = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: { 'x-apikey': apiKey, 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ url }),
            signal: controller.signal
        });
        if (!submit.ok) throw new Error(`VT submit failed ${submit.status}`);
        const subJson = await submit.json();
        const id = subJson?.data?.id;
        if (!id) throw new Error('No VT analysis id');

        // Poll up to ~6s
        const started = Date.now();
        let pollJson;
        while (Date.now() - started < timeoutMs - 1000) {
            const poll = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers: { 'x-apikey': apiKey } });
            pollJson = await poll.json();
            const status = pollJson?.data?.attributes?.status;
            if (status === 'completed') break;
            await sleep(700);
        }

        const stats = pollJson?.data?.attributes?.stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;

        // Score: normalized malicious/suspicious ratio
        const total = malicious + suspicious + harmless + undetected + 1e-9;
        const score = clamp01((malicious * 1.0 + suspicious * 0.6) / total);

        const reasons = [];
        if (malicious) reasons.push(`${malicious} engines flagged malicious`);
        if (suspicious) reasons.push(`${suspicious} engines flagged suspicious`);
        if (harmless) reasons.push(`${harmless} engines harmless`);

        return { score, counts: { malicious, suspicious, harmless, undetected }, reasons };
    } finally {
        clearTimeout(to);
    }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function clamp01(x) { return Math.max(0, Math.min(1, x)); }
