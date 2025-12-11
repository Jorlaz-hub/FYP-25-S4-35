(function () {
  // Gather script information
  var scripts = Array.prototype.slice.call(document.scripts).map(function (s) {
    return {
      src: s.src || null, 
      inlineLength: s.src ? 0 : (s.textContent || '').length,
      type: s.type || 'text/javascript',
      hasNonce: !!s.nonce,
      integrity: s.integrity || null,
      textSample: s.src ? '' : (s.textContent || '').slice(0, 2000)
    };
  });

  var inlineScripts = scripts.filter(function (s) { return !s.src; }).length;
  var externalScripts = scripts.length - inlineScripts;

  var thirdPartyScripts = 0;
  try {
    var pageOrigin = new URL(location.href).origin;
    scripts.forEach(function (s) {
      if (!s.src) return;
      try {
        var origin = new URL(s.src, location.href).origin;
        if (origin !== pageOrigin) thirdPartyScripts += 1;
      } catch (e) { /* ignore bad URLs */ }
    });
  } catch (e) { /* ignore */ }

  // Count inline event handlers
  var inlineEventHandlers = 0;
  var eventSelector = [
    'onclick','onload','onerror','oninput','onsubmit','onchange','onmouseover',
    'onfocus','onblur','onkeydown','onkeyup','onkeypress','ontouchstart',
    'ontouchend','ondrag','ondrop','oncontextmenu'
  ].map(function (n) { return '[' + n + ']'; }).join(',');
  if (eventSelector) {
    Array.prototype.slice.call(document.querySelectorAll(eventSelector)).forEach(function (el) {
      Array.prototype.slice.call(el.attributes).forEach(function (a) {
        if (a && a.name && a.name.toLowerCase().indexOf('on') === 0 && a.value) {
          inlineEventHandlers += 1;
        }
      });
    });
  }

  // Basic template markers and token hints in inline script text
  var inlineTextCombined = scripts.filter(function (s) { return !s.src; })
    .map(function (s) { return s.textSample || ''; })
    .join('\n')
    .slice(0, 50000);

  function countMatches(str, regex, cap) {
    var m, c = 0;
    while ((m = regex.exec(str)) !== null) {
      c += 1;
      if (cap && c >= cap) break;
    }
    return c;
  }

  var templateMarkers = inlineTextCombined
    ? (countMatches(inlineTextCombined, /\{\{[^}]+\}\}/g, 200) + countMatches(inlineTextCombined, /<%[^%]*%>/g, 200))
    : 0;

  var tokenHits = inlineTextCombined
    ? countMatches(inlineTextCombined, /(api[_-]?key|access[_-]?token|secret|bearer|authorization)\s*[:=]\s*['"][A-Za-z0-9_\-]{10,}/gi, 200)
    : 0;

  // Forms and CSRF tokens
  var formsTotal = document.forms ? document.forms.length : 0;
  var formsWithoutCsrf = 0;
  Array.prototype.slice.call(document.forms || []).forEach(function (form) {
    var hasToken = form.querySelector('input[name*="csrf" i], input[name*="xsrf" i], input[name*="token" i]');
    if (!hasToken) formsWithoutCsrf += 1;
  });

  var cspMeta = Array.prototype.slice
    .call(document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]'))
    .map(function (m) { return m.getAttribute('content'); });

  chrome.runtime.sendMessage({
    kind: 'pageScanResult',
    url: location.href,
    scripts: scripts,
    cspMeta: cspMeta,
    inlineScripts: inlineScripts,
    externalScripts: externalScripts,
    thirdPartyScripts: thirdPartyScripts,
    inlineEventHandlers: inlineEventHandlers,
    templateMarkers: templateMarkers,
    tokenHits: tokenHits,
    formsTotal: formsTotal,
    formsWithoutCsrf: formsWithoutCsrf
  });
})();
