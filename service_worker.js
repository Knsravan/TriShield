// background/service_worker.js
import { analyzeWithHeuristics } from './analysis.js';
import { vtAnalyze } from './vt.js';

const DEFAULTS = {
    enabled: true,
    blockRisky: true,
    vtApiKey: '',
    vtTimeoutMs: 12000,
    vtWeight: 0.7,
    heurWeight: 0.3,
    riskThreshold: 0.6,
    toastOnSafe: true,
    allowlist: []
};

chrome.runtime.onInstalled.addListener(async () => {
    const cur = await chrome.storage.local.get(Object.keys(DEFAULTS));
    const init = { ...DEFAULTS, ...cur };
    await chrome.storage.local.set(init);

    // context menu
    chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({
            id: 'trishield-scan-link',
            title: 'Scan link with TriShield',
            contexts: ['link']
        });
    });

    await migrateHistory(); // <-- make old history rows compatible
});

chrome.runtime.onStartup.addListener(migrateHistory);

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === 'trishield-scan-link' && info.linkUrl) {
        const verdict = await runFullAnalysis(info.linkUrl);
        await notifyVerdict(tab?.id, info.linkUrl, verdict);
        await saveHistory(verdict); // save flattened shape
    }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    (async () => {
        if (msg?.type === 'GET_SETTINGS') {
            const settings = await chrome.storage.local.get(Object.keys(DEFAULTS));
            sendResponse({ settings });
            return;
        }

        if (msg?.type === 'ANALYZE_URL') {
            const tabId = sender?.tab?.id;
            setBadge(tabId, 'SCAN');
            const verdict = await runFullAnalysis(msg.url);
            await notifyVerdict(tabId, msg.url, verdict);
            await saveHistory(verdict); // save flattened
            sendResponse({ verdict });
            return;
        }

        if (msg?.type === 'CLOSE_TAB') {
            if (sender?.tab?.id) chrome.tabs.remove(sender.tab.id);
            sendResponse({ ok: true });
            return;
        }

        if (msg?.type === 'SET_ENABLED') {
            await chrome.storage.local.set({ enabled: !!msg.enabled });
            if (sender?.tab?.id) setBadge(sender.tab.id, msg.enabled ? '' : 'OFF');
            sendResponse({ ok: true });
            return;
        }

        if (msg?.type === 'SCAN_ACTIVE_TAB') {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab?.url) { sendResponse({ error: 'No active tab' }); return; }
            setBadge(tab.id, 'SCAN');
            const verdict = await runFullAnalysis(tab.url);
            await notifyVerdict(tab.id, tab.url, verdict);
            await saveHistory(verdict);
            sendResponse({ verdict });
            return;
        }
    })();
    return true; // keep channel open
});

async function runFullAnalysis(url) {
    const settings = await chrome.storage.local.get(Object.keys(DEFAULTS));
    const { vtApiKey, vtTimeoutMs, vtWeight, heurWeight } = settings;

    // allowlist
    try {
        const host = new URL(url).hostname;
        const allowed = (settings.allowlist || []).some(d => host.endsWith(d));
        if (allowed) return mkVerdict(url, 0.0, 'safe', ['In user allowlist'], 'allowlist');
    } catch { }

    // heuristics
    const heur = analyzeWithHeuristics(url);

    // VirusTotal (optional)
    let vt = { score: null, reasons: [], counts: null };
    if (vtApiKey) {
        try {
            vt = await vtAnalyze(url, vtApiKey, vtTimeoutMs);
        } catch (e) {
            vt = { score: null, reasons: [`VT error: ${String(e).slice(0, 120)}`], counts: null };
        }
    }

    // fuse
    const vScore = vt.score ?? 0;
    const finalScore = clamp01(vScore * vtWeight + heur.score * heurWeight); // <-- clamp01 exists now
    const { riskThreshold = DEFAULTS.riskThreshold } = await chrome.storage.local.get(['riskThreshold']);
    const verdict = finalScore >= riskThreshold ? 'risk' : 'safe';

    return mkVerdict(url, finalScore, verdict, [...heur.reasons, ...(vt.reasons || [])], vt.score == null ? 'heuristics' : 'vt+heuristics', vt.counts);
}

async function notifyVerdict(tabId, url, result) {
    if (!tabId) return;
    if (result.verdict === 'risk') {
        setBadge(tabId, 'RISK');
        chrome.tabs.sendMessage(tabId, { type: 'SHOW_INTERSTITIAL', result });
    } else {
        setBadge(tabId, 'SAFE');
        const { toastOnSafe } = await chrome.storage.local.get(['toastOnSafe']);
        if (toastOnSafe) chrome.tabs.sendMessage(tabId, { type: 'SHOW_SAFE_TOAST', result });
    }
}

function setBadge(tabId, text) {
    if (!tabId) return;
    chrome.action.setBadgeText({ tabId, text: text || '' });
    chrome.action.setBadgeBackgroundColor({
        tabId,
        color: text === 'RISK' ? '#dc2626' : text === 'SAFE' ? '#16a34a' : '#4f46e5'
    });
}

// ---- storage: always save a flat history item
async function saveHistory(resultObj) {
    const entry = {
        url: resultObj.url || '',
        verdict: resultObj.verdict || 'safe', // string
        score: typeof resultObj.score === 'number' ? resultObj.score : 0,
        at: Date.now()
    };
    const { history = [] } = await chrome.storage.local.get(['history']);
    history.unshift(entry);
    if (history.length > 250) history.pop();
    await chrome.storage.local.set({ history });
}

// ---- migration: convert legacy rows to flat shape
async function migrateHistory() {
    const { history = [] } = await chrome.storage.local.get(['history']);
    if (!history.length) return;
    let mutated = false;
    const fixed = history.map(h => {
        if (typeof h.verdict === 'string') return h;
        mutated = true;
        return {
            url: h.url || (h.verdict && h.verdict.url) || '',
            verdict: (h.verdict && h.verdict.verdict) || 'safe',
            score: (h.verdict && typeof h.verdict.score === 'number') ? h.verdict.score : (h.score || 0),
            at: h.at || Date.now()
        };
    });
    if (mutated) await chrome.storage.local.set({ history: fixed });
}

// ---- utils
function clamp01(x) { return Math.max(0, Math.min(1, x)); }
function mkVerdict(url, score, verdict, reasons, source, vtCounts = null) {
    return { url, score, verdict, reasons, source, vtCounts, at: Date.now() };
}
