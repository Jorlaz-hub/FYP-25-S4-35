/**
 * Content Script
 * Runs directly in context of webpage, reponsible for:
 * 1. Scanning DOM for script tags, forms, inline event handlers
 * 2. Identify potential vulnerabilities using heuristics (pattern match)
 * 3. Observer current page for script injection (Single Page Applications)
 * 4. Send findings to background script for scores
 * * PRIVACY: No data sent or retrieved to or from external servers
 */

(function () {
  // scanTimeOut hold timer ID for debounce logic
  // stop scanner from scanner too often
  let scanTimeout;

  /**
   * CORE FUNCTION: runScan
   * encapsulate scanner logic to rerun whenever page changes
   */
  function runScan() {
    
    // --- SCAN SCRIPT TAGS ---
    // convert live HTMLcollection (document.scripts) to standard array
    var scripts = Array.prototype.slice.call(document.scripts).map(function (s) {
      return {
        // source URL (external), null (inline)
        src: s.src || null,
        
        // measure length of inline script
        // larger blocks increase risk of malicious code
        inlineLength: s.src ? 0 : (s.textContent || '').length,
        
        // capture type (e.g., 'module' or 'text/javascript')
        type: s.type || 'text/javascript',
        
        // check for 'nonce' (for Content Security Policy bypass prevention)
        hasNonce: !!s.nonce,
        
        // check for Subresource Integrity (SRI) hash
        // used for 3rd party scripts
        integrity: s.integrity || null,
        
        // extract text sample for secret testing
        textSample: s.src ? '' : (s.textContent || '').slice(0, 2000)
      };
    });

  function detectObfuscation(text) {
    if (!text || text.length < 60) return false;

      // Heuristic: Search for a continuous block of 60+ alphanumeric characters.
      var highEntropyPattern = /[A-Za-z0-9+/=]{40,}/;
      var packedPattern = /(eval\(function|\bwhile\s*\(\s*1\s*\)|function\(p,a,c,k,e,d\))/;

      return highEntropyPattern.test(text) || packedPattern.test(text);
    }

    var scripts = Array.prototype.slice.call(document.scripts).map(function (s) {
      var content = s.src ? '' : (s.textContent.trim() || '');

      return {
        src: s.src || null,
        inlineLength: s.src ? 0 : content.length,
        type: s.type || 'text/javascript',
        hasNonce: !!s.nonce,
        integrity: s.integrity || null,

        // Flag as true if the inline code matches obfuscation pattern
        isObfuscated: detectObfuscation(content),
        textSample: s.src ? '' : content.slice(0, 2000)
      };
    });

  

    // calculate high-level stats for the report
    var inlineScripts = scripts.filter(function (s) { return !s.src; }).length;
    var externalScripts = scripts.length - inlineScripts;

    // --- 3rd PARTY DETECTION ---
    // compare script origin domain to current page origin 
    var thirdPartyScripts = 0;
    try {
      var pageOrigin = new URL(location.href).origin;
      scripts.forEach(function (s) {
        if (!s.src) return;
        try {
          var origin = new URL(s.src, location.href).origin;
          // diff origin = 3rd party script (to improve)
          if (origin !== pageOrigin) thirdPartyScripts += 1;
        } catch (e) { /* Ignore invalid URLs */ }
      });
    } catch (e) { /* Ignore parsing errors */ }

    // --- INLINE EVENT HANDLER HEURISTICS ---
    // Legacy/Insecure pattern detection: <button onclick="...">
    // These are often blocked by strict CSPs and can be XSS vectors.
    var inlineEventHandlers = 0;
    
    // CSS selector for common event attributes
    var eventSelector = [
      'onclick','onload','onerror','oninput','onsubmit','onchange','onmouseover',
      'onfocus','onblur','onkeydown','onkeyup','onkeypress','ontouchstart',
      'ontouchend','ondrag','ondrop','oncontextmenu'
    ].map(function (n) { return '[' + n + ']'; }).join(',');
    
    if (eventSelector) {
      // query DOM for elements possessing these attributes
      Array.prototype.slice.call(document.querySelectorAll(eventSelector)).forEach(function (el) {
        Array.prototype.slice.call(el.attributes).forEach(function (a) {
          // double check starts with "on"
          if (a && a.name && a.name.toLowerCase().indexOf('on') === 0 && a.value) {
            inlineEventHandlers += 1;
          }
        });
      });
    }

    // --- SECRET & TEMPLATE INJECTION HEURISTICS ---
    // combine inline script text to search for bad patterns using regex
    // only scan first 50k char to prevent browser from freezing
    var inlineTextCombined = scripts.filter(function (s) { return !s.src; })
      .map(function (s) { return s.textSample || ''; })
      .join('\n')
      .slice(0, 50000);

    function countMatches(str, regex, cap) {
      var m, c = 0;
      while ((m = regex.exec(str)) !== null) {
        c += 1;
        if (cap && c >= cap) break; // safety cap for performance
      }
      return c;
    }

    // Check for Template Injection (SSTI)
    // {{...}} or <%...%> may indicate leaking serverside logics
    var templateMarkers = inlineTextCombined
      ? (countMatches(inlineTextCombined, /\{\{[^}]+\}\}/g, 200) + countMatches(inlineTextCombined, /<%[^%]*%>/g, 200))
      : 0;

    // Check for Hardcoded Secrets
    // Variable assignments like "api_key = '...'" or "Bearer '...'"
    var tokenHits = inlineTextCombined
      ? countMatches(inlineTextCombined, /(api[_-]?key|access[_-]?token|secret|bearer|authorization)\s*[:=]\s*['"][A-Za-z0-9_\-]{10,}/gi, 200)
      : 0;

    // --- ENHANCED FORM ANALYSIS ---
    var formsTotal = document.forms ? document.forms.length : 0;
    var formsWithoutCsrf = 0;
    var insecureForms = 0; 
    
    Array.prototype.slice.call(document.forms || []).forEach(function (form) {
      // CRSF check
      var hasToken = form.querySelector('input[name*="csrf" i], input[name*="xsrf" i], input[name*="token" i]');
      if (!hasToken) formsWithoutCsrf += 1;

      // GET method in forms for passwords 
      // sensitive data leak risks
      var method = (form.getAttribute('method') || 'GET').toUpperCase();
      var hasPassword = form.querySelector('input[type="password"]');
      if (method === 'GET' && hasPassword) {
        insecureForms += 1;
      }

      // check for external form action 
      // forms submitting data to external domains
      if (form.action) {
        try {
          var actionOrigin = new URL(form.action).origin;
          var pageOrigin = window.location.origin;
          // flag valid actions that have different origin domains
          if (actionOrigin !== 'null' && actionOrigin !== pageOrigin) {
            insecureForms += 1;
          }
        } catch (e) { /* ignore relative paths */ }
      }
    });

    // --- REVERSE TABNABBING ---
    // links with target="_blank" allow the new page to control the previous page
    // via 'window.opener' unless 'rel="noopener"' is used.
    var unsafeLinks = 0;
    var externalLinks = document.querySelectorAll('a[target="_blank"]');
    externalLinks.forEach(function(link) {
      var rel = (link.rel || '').toLowerCase();
      // Safe links must have 'noopener' or 'noreferrer'
      if (rel.indexOf('noopener') === -1 && rel.indexOf('noreferrer') === -1) {
        unsafeLinks += 1;
      }
    });

    // --- META TAG ANALYSIS ---
    // check if CSP defined in <meta> tag
    var cspMeta = Array.prototype.slice
      .call(document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]'))
      .map(function (m) { return m.getAttribute('content'); });

    // --- SEND RESULTS ---
    // ensure extension context remains valid
    // if extension updated / reloaded trigger error on chrome runtime 
    if (!chrome.runtime || !chrome.runtime.id) {
      console.log('Extension context invalidated. Stopping scan to prevent errors.');
      return;
    }

    // send findings to background js for store and scan
    try {
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
        formsWithoutCsrf: formsWithoutCsrf,

        insecureForms: insecureForms, // Forms with GET-passwords or external actions
        unsafeLinks: unsafeLinks      // Links vulnerable to reverse tabnabbing
      });
    } catch (e) {
      // Catch "Extension context invalidated" errors that occur during the send itself
    }
  }

  // --- EXECUTION START ---

  // run scan on script load (document end)
  runScan();

  // setup SPA support (MutationObserver)
  // watch <body> for injected nodes and dynamic updates
  var observer = new MutationObserver(function(mutations) {
    // debounce logic
    // make sure changes pause for 1 sec before rescan 
    clearTimeout(scanTimeout);
    scanTimeout = setTimeout(runScan, 1000);
  });

  // observing 
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }

})();
