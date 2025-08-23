const els = {
    vtKey: document.getElementById('vtKey'),
    threshold: document.getElementById('threshold'),
    thVal: document.getElementById('thVal'),
    blockRisky: document.getElementById('blockRisky'),
    toastSafe: document.getElementById('toastSafe'),
    allowInput: document.getElementById('allowInput'),
    addAllow: document.getElementById('addAllow'),
    allowList: document.getElementById('allowList'),
    save: document.getElementById('save'),
    saved: document.getElementById('saved')
};

(async function init() {
    const s = await chrome.storage.local.get(['vtApiKey', 'riskThreshold', 'blockRisky', 'toastOnSafe', 'allowlist']);
    els.vtKey.value = s.vtApiKey || 'eafe0662da9cd038e284e047c6068f7b9b271ca0e6aed2fb2c042ca50d85625b';
    els.threshold.value = Math.round((s.riskThreshold ?? 0.6) * 100);
    els.thVal.textContent = els.threshold.value;
    els.blockRisky.checked = !!s.blockRisky;
    els.toastSafe.checked = s.toastOnSafe !== false;
    renderAllow(s.allowlist || []);
})();

els.threshold.addEventListener('input', () => els.thVal.textContent = els.threshold.value);
els.addAllow.addEventListener('click', async () => {
    const d = (els.allowInput.value || '').trim().toLowerCase();
    if (!d) return; const { allowlist = [] } = await chrome.storage.local.get(['allowlist']);
    if (!allowlist.includes(d)) allowlist.push(d);
    await chrome.storage.local.set({ allowlist });
    els.allowInput.value = ''; renderAllow(allowlist);
});

els.save.addEventListener('click', async () => {
    await chrome.storage.local.set({
        vtApiKey: els.vtKey.value.trim(),
        riskThreshold: (+els.threshold.value) / 100,
        blockRisky: els.blockRisky.checked,
        toastOnSafe: els.toastSafe.checked
    });
    els.saved.classList.add('show');
    setTimeout(() => els.saved.classList.remove('show'), 1400);
});

async function renderAllow(list) {
    els.allowList.innerHTML = '';
    list.forEach((d, idx) => {
        const li = document.createElement('li');
        li.textContent = d;
        const btn = document.createElement('button'); btn.textContent = 'Remove'; btn.className = 'btn'; btn.style.padding = '6px 10px'; btn.style.fontWeight = '600';
        btn.addEventListener('click', async () => {
            const { allowlist = [] } = await chrome.storage.local.get(['allowlist']);
            allowlist.splice(idx, 1); await chrome.storage.local.set({ allowlist }); renderAllow(allowlist);
        });
        li.appendChild(btn); els.allowList.appendChild(li);
    });
}
