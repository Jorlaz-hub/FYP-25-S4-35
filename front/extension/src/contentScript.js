(function () {
  var scripts = Array.prototype.slice.call(document.scripts).map(function (s) {
    return {
      src: s.src || null,
      inlineLength: s.src ? 0 : (s.textContent || '').length,
      type: s.type || 'text/javascript',
      hasNonce: !!s.nonce,
      integrity: s.integrity || null
    };
  });

  var cspMeta = Array.prototype.slice
    .call(document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]'))
    .map(function (m) { return m.getAttribute('content'); });

  chrome.runtime.sendMessage({
    kind: 'pageScanResult',
    url: location.href,
    scripts: scripts,
    cspMeta: cspMeta
  });
})();
