// ui/dashboard.js
const scanBtn = document.getElementById('scanBtn');
const scanInput = document.getElementById('scanInput');
const tbody = document.querySelector('#tbl tbody');
const meta = document.getElementById('meta');

scanBtn.addEventListener('click', async () => {
    const url = (scanInput.value || '').trim();
    if (!url) return;
    const res = await chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url });
    // Save to history is done in background; still render the result immediately
    renderRow(res?.verdict || null, true);
});

(async function init() {
    const { history = [] } = await chrome.storage.local.get(['history']);
    meta.textContent = `Total scanned: ${history.length}`;
    history.slice(0, 100).forEach(v => renderRow(v));
})();

function renderRow(v, prepend) {
    if (!v) return;
    const n = normalize(v); // <- supports old/new shapes
    const tr = document.createElement('tr');
    const when = new Date(n.at).toLocaleString();
    const score = Math.round((n.score || 0) * 100);

    const verdictText = (typeof n.verdict === 'string' ? n.verdict : 'safe').toUpperCase();
    const verdictClass = (typeof n.verdict === 'string' ? n.verdict : 'safe');

    tr.innerHTML = `<td>${when}</td>
                  <td>${escapeHtml(n.url)}</td>
                  <td><span class="badge ${verdictClass}">${verdictText}</span></td>
                  <td>${score}</td>`;
    if (prepend) tbody.prepend(tr); else tbody.appendChild(tr);
}

// Accepts:
// old: { url, verdict:{ verdict, score, url }, at }
// new: { url, verdict:'safe'|'risk', score, at }
function normalize(v) {
    const verdictStr = typeof v.verdict === 'string'
        ? v.verdict
        : (v.verdict && v.verdict.verdict) || 'safe';

    const scoreNum = (typeof v.score === 'number')
        ? v.score
        : ((v.verdict && typeof v.verdict.score === 'number') ? v.verdict.score : 0);

    const urlStr = v.url || (v.verdict && v.verdict.url) || '';

    return {
        url: urlStr,
        verdict: verdictStr,
        score: scoreNum,
        at: v.at || Date.now()
    };
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
}
