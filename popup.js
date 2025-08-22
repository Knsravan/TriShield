document.addEventListener('DOMContentLoaded', () => {
  const statusContainer = document.getElementById('status-container');
  const resultsContainer = document.getElementById('results-container');

  function showStatus(message, type) {
    statusContainer.innerHTML = `<div class="status-message ${type}">${message}</div>`;
    resultsContainer.innerHTML = ''; // Clear previous results
  }

  function renderResults(results) {
    statusContainer.innerHTML = ''; // Clear status message
    if (!Array.isArray(results) || results.length === 0) {
      showStatus('✅ No threats found on this page.', 'safe');
      return;
    }

    const html = results.map(res => `
      <div class="result-card ${res.verdict.toLowerCase()}">
        <div class="result-header">
          <span class="verdict ${res.verdict.toLowerCase()}">${res.verdict}</span>
          <span class="score">Score: ${res.score}</span>
        </div>
        <div class="result-url">${res.url}</div>
        <div class="result-details">
          ${res.details.blacklist ? `<div class="detail"><strong>Blacklist:</strong> ${res.details.blacklist}</div>` : ''}
          ${res.details.typosquatting ? `<div class="detail"><strong>TypoSquatting:</strong> Looks like <strong>${res.details.typosquatting.original}</strong>, not ${res.details.typosquatting.detected}.</div>` : ''}
          ${res.details.virustotal ? `<div class="detail"><strong>Reputation:</strong> ${res.details.virustotal}</div>` : ''}
        </div>
      </div>
    `).join('');

    resultsContainer.innerHTML = html;
  }

  function isAllowedUrl(url) {
    if (!url) return false;
    const forbiddenPrefixes = ['chrome://', 'about:', 'chrome-extension://'];
    return url.startsWith('http') && !forbiddenPrefixes.some(p => url.startsWith(p));
  }

  // --- Main Execution ---

  showStatus('Analyzing links on this page...', 'loading');

  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab || !isAllowedUrl(tab.url)) {
      showStatus('This page cannot be analyzed.<br/>Please open a regular website.', 'warning');
      return;
    }

    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['js/content.js']
    }).catch(err => {
      showStatus('Could not run analyzer on this page.', 'warning');
      console.error('Script injection failed:', err);
    });
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === 'analysisResults') {
      renderResults(msg.results);
    }
  });
});