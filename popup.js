const toggleEl = document.getElementById('toggle');
const statusEl = document.getElementById('statusText');
const scoreEl = document.getElementById('score');

document.getElementById('scanBtn').addEventListener('click', async () => {
    const res = await chrome.runtime.sendMessage({ type: 'SCAN_ACTIVE_TAB' });
    render(res?.verdict);
});

for (const id of ['dashboard', 'options']) {
    document.getElementById(id).addEventListener('click', () => {
        const page = id === 'dashboard' ? 'dashboard.html' : 'options.html';
        chrome.tabs.create({ url: chrome.runtime.getURL('ui/' + page) });
    });
}

(async function init() {
    const { settings } = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    toggleEl.checked = !!settings.enabled;
    toggleEl.addEventListener('change', () => {
        chrome.runtime.sendMessage({ type: 'SET_ENABLED', enabled: toggleEl.checked });
        statusEl.textContent = toggleEl.checked ? 'Enabled' : 'Disabled';
    });

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
        scoreEl.textContent = 'Current tab: ' + (new URL(tab.url).hostname);
    }
    statusEl.textContent = toggleEl.checked ? 'Enabled' : 'Disabled';
})();

function render(v) {
    if (!v) return;
    statusEl.textContent = v.verdict === 'risk' ? 'RISK' : 'SAFE';
    const pct = Math.round((v.score || 0) * 100);
    scoreEl.textContent = `Score: ${pct}/100 · ${v.source}`;
}
