(function() {
  function extractLinks() {
    try {
      const anchors = Array.from(document.querySelectorAll('a'));
      const links = anchors.map(a => a && a.href ? a.href : '')
        .filter(href => /^https?:/i.test(href));
      if (links.length) {
        chrome.runtime.sendMessage({ action: 'analyzeLinks', links });
      } else {
        // Still notify so popup can show "No threats"
        chrome.runtime.sendMessage({ action: 'analyzeLinks', links: [] });
      }
    } catch (e) {
      // Ignore
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', extractLinks, { once: true });
  } else {
    extractLinks();
  }

  const target = document.body || document.documentElement;
  try {
    new MutationObserver(() => extractLinks())
      .observe(target, { childList: true, subtree: true });
  } catch (e) {
    // Ignore if page disallows observers
  }
})();