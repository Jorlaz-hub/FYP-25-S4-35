(function () {
  var HEALTH_COLORS = {
    unsafe: '#ef4444',
    poor: '#f59e0b',
    passed: '#22c55e',
    ready: '#eab308',
    offline: '#94a3b8'
  };
  var CHECKS_KEY = 'checksConfig';
  var DEFAULT_CHECKS = SharedAlgo.DEFAULT_CHECKS;
  var normalizeChecks = SharedAlgo.normalizeChecks;
  var computeAreaScores = SharedAlgo.computeAreaScores;

  var checksConfig = normalizeChecks(null);

  function setGauge(idPrefix, val, sev) {
    var ring = document.getElementById('ring' + idPrefix);
    var score = document.getElementById('score' + idPrefix);
    var sevEl = document.getElementById('sev' + idPrefix);
    var color = HEALTH_COLORS[sev] || '#94a3b8';
    if (ring) {
      ring.style.setProperty('--health-angle', ((val / 100) * 360) + 'deg');
      ring.style.setProperty('--health-color', color);
    }
    if (score) score.textContent = (val ? val.toFixed(2) : '0') + '%';
    if (sevEl) sevEl.textContent = sev.toUpperCase();
  }

  function renderFindings(info) {
    var container = document.getElementById('findings');
    if (!container) return;
    container.innerHTML = '';
    var templateMarkers = info.templateMarkersUnsafe != null ? info.templateMarkersUnsafe : (info.templateMarkers || 0);
    var tokenHits = info.tokenHitsUnsafe != null ? info.tokenHitsUnsafe : (info.tokenHits || 0);
    var formsWithoutCsrf = info.formsWithoutCsrfUnsafe != null ? info.formsWithoutCsrfUnsafe : (info.formsWithoutCsrf || 0);
    var items = [
      { title: 'Scripts', body: 'Total: ' + info.scripts.length + '; Inline: ' + (info.inlineScripts || 0) + '; External: ' + (info.externalScripts || (info.scripts.length - (info.inlineScripts || 0))) + '; Third-party: ' + (info.thirdPartyScripts || 0) },
      { title: 'CSP Meta Tags', body: (info.cspMeta && info.cspMeta.length ? 'Present (' + info.cspMeta.length + ')' : 'Missing') },
      { title: 'Inline Event Handlers', body: String(info.inlineEventHandlers || 0) },
      { title: 'Template markers', body: String(templateMarkers) },
      { title: 'Token-like strings detected', body: String(tokenHits) },
      { title: 'Forms without CSRF tokens', body: String(formsWithoutCsrf) + ' of ' + String(info.formsTotal || 0) }
    ];
    items.forEach(function (it) {
      var block = document.createElement('div');
      block.className = 'finding';
      var t = document.createElement('div');
      t.className = 'finding-title';
      t.textContent = it.title;
      var b = document.createElement('p');
      b.className = 'finding-body';
      b.textContent = it.body;
      block.appendChild(t);
      block.appendChild(b);
      container.appendChild(block);
    });
  }

  function renderAreaCards(info, areas) {
    var container = document.getElementById('areas');
    if (!container) return;
    container.innerHTML = '';

    var pageOrigin = null;
    try { pageOrigin = new URL(info.url).origin; } catch (e) {}
    var inlineCount = info.inlineScripts != null ? info.inlineScripts : info.scripts.filter(function (s) { return !s.src; }).length;
    var thirdParty = info.thirdPartyScripts != null ? info.thirdPartyScripts : (function(){
      var n = 0;
      (info.scripts || []).forEach(function (s) {
        if (s.src) {
          try { if (new URL(s.src, info.url).origin !== pageOrigin) n += 1; } catch (e) {}
        }
      });
      return n;
    })();
    var noIntegrity = (info.scripts || []).filter(function (s) { return !!s.src && !s.integrity; }).length;
    var headers = info.responseHeaders || {}; var hdrs = {}; Object.keys(headers).forEach(function (k) { hdrs[k.toLowerCase()] = headers[k]; });
    var hasCspHeader = !!hdrs['content-security-policy'];

    function barColor(sev) {
      return HEALTH_COLORS[sev] || '#94a3b8';
    }

    function mkInsight(title, body) {
      var d = document.createElement('details');
      var s = document.createElement('summary'); s.textContent = title;
      d.appendChild(s);
      if (Array.isArray(body)) {
        body.forEach(function (node) {
          if (node && (node.nodeType === 1 || node.nodeType === 3)) {
            d.appendChild(node);
          } else {
            var p = document.createElement('p');
            p.textContent = String(node);
            d.appendChild(p);
          }
        });
      } else if (body && (body.nodeType === 1 || body.nodeType === 3)) {
        d.appendChild(body);
      } else {
        var p = document.createElement('p');
        p.textContent = String(body || '');
        d.appendChild(p);
      }
      return d;
    }

    function createSnippetTabs(snippets, cap) {
      var wrap = document.createElement('div');
      wrap.className = 'snippet-tabs';
      var tabs = document.createElement('div');
      tabs.className = 'tab-list';
      var panel = document.createElement('div');
      panel.className = 'tab-panel';

      var activeIndex = 0;

      function renderPanel(idx) {
        panel.innerHTML = '';
        var s = snippets[idx];
        var hdr = document.createElement('div');
        hdr.className = 'snippet-label';
        var len = s.inlineLength != null ? s.inlineLength : (s.textSample || '').length;
        hdr.textContent = 'Snippet #' + (idx + 1) + ' (' + len + ' chars)';
        var pre = document.createElement('pre');
        pre.className = 'insight-snippet';
        pre.textContent = s.textSample || '';
        panel.appendChild(hdr);
        panel.appendChild(pre);
      }

      snippets.slice(0, cap).forEach(function (s, idx) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'tab-btn' + (idx === 0 ? ' active' : '');
        btn.textContent = String(idx + 1);
        btn.addEventListener('click', function () {
          var all = tabs.querySelectorAll('.tab-btn');
          all.forEach(function (b) { b.classList.remove('active'); });
          btn.classList.add('active');
          activeIndex = idx;
          renderPanel(activeIndex);
        });
        tabs.appendChild(btn);
      });

      renderPanel(activeIndex);
      wrap.appendChild(tabs);
      wrap.appendChild(panel);

      if (snippets.length > cap) {
        var more = document.createElement('p');
        more.className = 'snippet-more';
        more.textContent = 'Showing ' + cap + ' of ' + snippets.length + ' inline scripts.';
        wrap.appendChild(more);
      }

      return wrap;
    }

    function card(areaKey, title, score, sev, insightItems, themeClass) {
      var card = document.createElement('section');
      card.className = 'area-card ' + themeClass;
      var color = HEALTH_COLORS[sev] || '#94a3b8';
      // tint background and border using HEALTH_COLORS
      card.style.background = color + '1a';
      card.style.borderColor = color + '33';
      var h = document.createElement('h2'); h.className = 'area-title'; h.textContent = title;
      var sub = document.createElement('div'); sub.className = 'area-subtitle'; sub.textContent = title + ' Health:';
      var prog = document.createElement('div'); prog.className = 'progress';
      var bar = document.createElement('div'); bar.className = 'bar'; bar.style.background = barColor(sev); bar.style.width = Math.round(score) + '%';
      var val = document.createElement('div'); val.className = 'value'; val.textContent = (score ? score.toFixed(2) : '0') + '%';
      prog.appendChild(bar); prog.appendChild(val);
      var insights = document.createElement('div'); insights.className = 'insights';
      var ih = document.createElement('h4'); ih.textContent = 'Insights'; insights.appendChild(ih);
      insightItems.forEach(function (it) { insights.appendChild(mkInsight(it.title, it.body)); });
      card.appendChild(h); card.appendChild(sub); card.appendChild(prog); card.appendChild(insights);
      container.appendChild(card);
    }

    // Build insights from available metrics to avoid speculative claims
    var structureInsights = [
      inlineCount > 0 ?
        { title: 'Inline scripts detected', body: inlineCount + ' inline <script> tag(s) present. Consider moving to external files.' } :
        { title: 'No inline scripts detected', body: 'All script code appears to be externalized.' },
      { title: 'Template markers', body: String(info.templateMarkers || 0) + ' potential template markers found.' },
      { title: 'Inline event handlers', body: String(info.inlineEventHandlers || 0) + ' inline event handler(s) detected.' }
    ];

    // Integrate inline script snippet previews into the "Inline scripts detected" insight using tabs
    try {
      if (inlineCount > 0) {
        var inlineScriptsList = (info.scripts || []).filter(function (s) { return !s.src && (s.textSample || '').length; });
        var bodyNodes = [];
        var intro = document.createElement('p');
        intro.textContent = inlineCount + ' inline <script> tag(s) present. Consider moving to external files.';
        bodyNodes.push(intro);
        if (inlineScriptsList.length) {
          var cap = 10;
          bodyNodes.push(createSnippetTabs(inlineScriptsList, cap));
        } else {
          var none = document.createElement('p');
          none.textContent = 'No inline snippet captured.';
          bodyNodes.push(none);
        }
        structureInsights[0] = { title: 'Inline scripts detected', body: bodyNodes };
      }
    } catch (e) {
      // Keep original insight text on failure
    }

    var securityInsights = [
      hasCspHeader ?
        { title: 'CSP header present', body: 'Content-Security-Policy header detected.' } :
        { title: 'No CSP header', body: 'No CSP response header detected; consider adding one.' },
      { title: 'SRI on external scripts', body: (info.scripts.length - noIntegrity - inlineCount) + ' with SRI, ' + noIntegrity + ' without.' },
      { title: 'Security headers', body: 'HSTS: ' + (!!hdrs['strict-transport-security']) + ', X-CTO: ' + (!!hdrs['x-content-type-options']) + ', Referrer-Policy: ' + (!!hdrs['referrer-policy']) }
    ];

    var exposureInsights = [
      { title: 'Third-party scripts', body: thirdParty + ' script(s) loaded from third-party origins.' },
      { title: 'Token-like strings', body: String(info.tokenHitsUnsafe != null ? info.tokenHitsUnsafe : (info.tokenHits || 0)) + ' potential token/secret matches.' },
      { title: 'Forms without CSRF', body: String(info.formsWithoutCsrfUnsafe != null ? info.formsWithoutCsrfUnsafe : (info.formsWithoutCsrf || 0)) + ' of ' + String(info.formsTotal || 0) }
    ];

    card('structure', 'Structure', areas.structure.score, areas.structure.severity, structureInsights, 'structure');
    card('security', 'Security', areas.security.score, areas.security.severity, securityInsights, 'security');
    card('exposure', 'Exposure', areas.exposure.score, areas.exposure.severity, exposureInsights, 'exposure');
  }

  function handleDownload(data, areas) {
    var payload = {
      url: data.url,
      scannedAt: data.ts ? new Date(data.ts).toISOString() : null,
      health: areas.overall,
      areas: areas,
      scripts: data.result.scripts,
      cspMeta: data.result.cspMeta,
      responseHeaders: data.result.responseHeaders || {},
      inlineEventHandlers: data.result.inlineEventHandlers,
      templateMarkers: data.result.templateMarkers,
      tokenHits: data.result.tokenHitsUnsafe != null ? data.result.tokenHitsUnsafe : data.result.tokenHits,
      formsWithoutCsrf: data.result.formsWithoutCsrfUnsafe != null ? data.result.formsWithoutCsrfUnsafe : data.result.formsWithoutCsrf,
      formsTotal: data.result.formsTotal
    };
    var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    var blobUrl = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = blobUrl;
    a.download = 'script-inspector-report.json';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    }, 50);
  }

  function init() {
    chrome.storage.local.get(['reviewTargetKey', CHECKS_KEY], function (cfg) {
      checksConfig = normalizeChecks(cfg[CHECKS_KEY]);
      var key = cfg.reviewTargetKey;
      if (!key) {
        document.getElementById('sourceUrl').textContent = 'No review target found. Run a scan from the popup.';
        return;
      }
      chrome.storage.local.get([key], function (data) {
        var list = data[key] || [];
        if (!list.length) {
          document.getElementById('sourceUrl').textContent = 'No scan data found for this page.';
          return;
        }
        var entry = list[0];
        var info = entry.result;
        document.getElementById('sourceUrl').textContent = info.url;
        var areas = computeAreaScores(info, checksConfig);

        setGauge('Overall', areas.overall.score, areas.overall.severity);
        setGauge('Structure', areas.structure.score, areas.structure.severity);
        setGauge('Security', areas.security.score, areas.security.severity);
        setGauge('Exposure', areas.exposure.score, areas.exposure.severity);

        renderFindings(info);
        renderAreaCards(info, areas);

        var dl = document.getElementById('downloadBtn');
        if (dl) {
          dl.addEventListener('click', function () { handleDownload(entry, areas); });
        }
      });
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
