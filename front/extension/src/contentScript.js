// Content script runs in an isolated world: it can read
// the DOM but not page-defined JS variables/functions.
// Our approach:
// 1) Enumerate all <script> elements and collect metadata.
// 2) Read inline scripts via textContent.
// 3) Try fetching external scripts (same-origin/CORS allowed).
// 4) If fetch fails (likely due to CORS), ask background to fetch.
// 5) Send results to background for storage/inspection.
// WIP

(function () {
  var toArray = function (list) { return Array.prototype.slice.call(list); };

  // Collect basic script tag info for quick overview.
  var scriptEls = toArray(document.scripts);
  var scriptSummaries = scriptEls.map(function (s, idx) {
    return {
      index: idx,
      src: s.src || null,
      type: s.type || 'text/javascript',
      hasNonce: !!s.nonce,
      integrity: s.integrity || null,
      inlineLength: s.src ? 0 : (s.textContent || '').length
    };
  });

  // For each script, either read inline content or try to fetch.
  var capturePromises = scriptEls.map(function (s, idx) {
    if (s.src) {
      // External script: try direct fetch first. This works when
      // same-origin or the server allows CORS for the extension.
      return fetch(s.src, { credentials: 'include' })
        .then(function (res) {
          if (!res.ok) throw new Error('HTTP ' + res.status);
          return res.text();
        })
        .then(function (text) {
          return { index: idx, kind: 'external', url: s.src, content: text };
        })
        .catch(function (err) {
          // If blocked, ask the background service worker to fetch.
          return new Promise(function (resolve) {
            chrome.runtime.sendMessage(
              { kind: 'fetchScriptInBackground', url: s.src, index: idx },
              function (resp) {
                if (resp && resp.ok) {
                  resolve({ index: idx, kind: 'external', url: s.src, content: resp.content });
                } else {
                  resolve({ index: idx, kind: 'external-error', url: s.src, error: (resp && resp.error) || String(err) });
                }
              }
            );
          });
        });
    } else {
      // Inline script: safe to read directly.
      return Promise.resolve({ index: idx, kind: 'inline', content: s.textContent || '' });
    }
  });

  // Capture CSP meta tags that influence script execution.
  var cspMeta = toArray(document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]'))
    .map(function (m) { return m.getAttribute('content'); });

  // Wait for all captures (including background fallbacks), then send.
  Promise.allSettled(capturePromises).then(function (results) {
    var collected = results.map(function (r) {
      return r.status === 'fulfilled' ? r.value : { kind: 'error', error: String(r.reason) };
    });

    chrome.runtime.sendMessage({
      kind: 'pageScanResult',
      url: location.href,
      scripts: scriptSummaries,
      cspMeta: cspMeta,
      collected: collected
    });
  });
})();
