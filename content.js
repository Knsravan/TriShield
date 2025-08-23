// content/content.js
(function () {
    let overlayShown = false;
    let settings = {};

    chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, ({ settings: s }) => { settings = s || {}; boot(); });

    function boot() {
        if (!settings.enabled) return; // respect toggle
        const url = location.href;
        // Show analyzing overlay immediately; we'll switch to SAFE toast later if needed
        showOverlay({ mode: 'scan' });
        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, ({ verdict }) => {
            if (!verdict) return; // safety
            if (verdict.verdict === 'risk') {
                updateOverlayRisk(verdict);
            } else {
                removeOverlay();
                chrome.runtime.sendMessage({ type: 'SAFE_TOAST_ALLOWED' });
            }
        });
    }

    chrome.runtime.onMessage.addListener((msg) => {
        if (msg?.type === 'SHOW_INTERSTITIAL') updateOverlayRisk(msg.result);
        if (msg?.type === 'SHOW_SAFE_TOAST') showSafeToast(msg.result);
    });

    // UI helpers
    function showOverlay({ mode }) {
        if (overlayShown) return; overlayShown = true;
        const root = document.createElement('div');
        root.className = 'tri-overlay';
        root.innerHTML = `
      <div class="tri-card">
        <div class="tri-badge ${mode === 'scan' ? 'scan' : ''}">
          <span class="tri-spinner"></span>
          <span>Analyzing this site…</span>
        </div>
        <div class="tri-title">Hold on while TriShield checks safety</div>
        <div class="tri-sub">We’re checking VirusTotal and AI heuristics. This prevents harmful pages from loading unnoticed.</div>
        <ul class="tri-reasons"></ul>
        <div class="tri-actions">
          <button class="tri-btn ghost" id="tri-continue" style="display:none">Proceed anyway</button>
          <button class="tri-btn primary" id="tri-leave" style="display:none">Leave site</button>
        </div>
      </div>`;
        document.documentElement.appendChild(root);

        root.querySelector('#tri-continue')?.addEventListener('click', () => {
            removeOverlay();
        });
        root.querySelector('#tri-leave')?.addEventListener('click', () => {
            chrome.runtime.sendMessage({ type: 'CLOSE_TAB' });
        });
    }

    function updateOverlayRisk(result) {
        // Switch to RISK mode
        const root = ensureOverlay();
        const badge = root.querySelector('.tri-badge');
        badge.classList.remove('scan');
        badge.classList.add('risk');
        badge.innerHTML = '⚠️ Potentially Harmful';

        root.querySelector('.tri-title').textContent = 'This site may be harmful';
        root.querySelector('.tri-sub').textContent = describeRisk(result);

        const ul = root.querySelector('.tri-reasons');
        ul.innerHTML = '';
        (result.reasons || []).slice(0, 6).forEach(r => {
            const li = document.createElement('li'); li.textContent = '• ' + r; ul.appendChild(li);
        });

        root.querySelector('#tri-continue').style.display = 'inline-flex';
        root.querySelector('#tri-leave').style.display = 'inline-flex';
    }

    function describeRisk(r) {
        const vt = r.vtCounts;
        const vtLine = vt ? `${vt.malicious || 0} malicious / ${vt.suspicious || 0} suspicious engine votes` : 'heuristic indicators present';
        return `Opening may expose your device or data. ${vtLine}.`;
    }

    function showSafeToast(result) {
        const t = document.createElement('div');
        t.className = 'tri-toast';
        t.textContent = 'This website looks safe. You can proceed ✅';
        document.documentElement.appendChild(t);
        setTimeout(() => { t.remove(); }, 2500);
    }

    function removeOverlay() {
        const el = document.querySelector('.tri-overlay');
        if (el) el.remove(); overlayShown = false;
    }

    function ensureOverlay() {
        let el = document.querySelector('.tri-overlay');
        if (!el) { showOverlay({ mode: 'scan' }); el = document.querySelector('.tri-overlay'); }
        return el;
    }
})();
