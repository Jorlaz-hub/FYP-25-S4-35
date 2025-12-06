(function () {
  var HEALTH_COLORS = {
    unsafe: '#ef4444',
    poor: '#f59e0b',
    passed: '#22c55e',
    ready: '#eab308',
    offline: '#94a3b8'
  };

  function clamp(n, min, max) { return Math.max(min, Math.min(max, n)); }
  function severity(val) { return val < 40 ? 'unsafe' : val <= 75 ? 'poor' : 'passed'; }

  function computeAreaScores(info) {
    if (!info || !info.scripts) {
      return {
        structure: { score: 0, severity: 'ready' },
        security: { score: 0, severity: 'ready' },
        exposure: { score: 0, severity: 'ready' },
        overall: { score: 0, severity: 'ready' }
      };
    }

    var inlineCount = info.inlineScripts != null ? info.inlineScripts : info.scripts.filter(function (s) { return !s.src; }).length;
    var thirdParty = info.thirdPartyScripts != null ? info.thirdPartyScripts : 0;
    if (thirdParty === 0) {
      try {
        var pageOrigin = new URL(info.url).origin;
        info.scripts.forEach(function (s) {
          if (s.src) {
            try {
              var scriptOrigin = new URL(s.src, info.url).origin;
              if (scriptOrigin !== pageOrigin) thirdParty += 1;
            } catch (e) {}
          }
        });
      } catch (e) {}
    }

    var noIntegrity = info.scripts.filter(function (s) { return !!s.src && !s.integrity; }).length;
    var noCsp = (info.cspMeta || []).length === 0;
    var inlineEvents = info.inlineEventHandlers || 0;
    var templateMarkers = info.templateMarkers || 0;
    var tokenHits = info.tokenHits || 0;
    var formsWithoutCsrf = info.formsWithoutCsrf || 0;

    var structure = 100;
    structure -= clamp(inlineCount * 3, 0, 25);
    structure -= clamp(inlineEvents * 2, 0, 20);
    structure -= clamp(templateMarkers * 3, 0, 15);

    var security = 100;
    if (noCsp) security -= 15;
    security -= clamp(noIntegrity * 2, 0, 16);
    security -= clamp(thirdParty * 2, 0, 16);
    security -= clamp(inlineCount * 1.5, 0, 15);
    try {
      if (new URL(info.url).protocol !== 'https:') security -= 10;
    } catch (e) {}

    var exposure = 100;
    exposure -= clamp(formsWithoutCsrf * 5, 0, 25);
    exposure -= clamp(tokenHits * 4, 0, 20);
    exposure -= clamp(thirdParty * 2, 0, 20);
    exposure -= clamp(inlineCount * 1, 0, 10);

    structure = clamp(structure, 0, 100);
    security = clamp(security, 0, 100);
    exposure = clamp(exposure, 0, 100);

    var overallScore = Math.round(((structure + security + exposure) / 3) * 100) / 100;

    return {
      structure: { score: Math.round(structure * 100) / 100, severity: severity(structure) },
      security: { score: Math.round(security * 100) / 100, severity: severity(security) },
      exposure: { score: Math.round(exposure * 100) / 100, severity: severity(exposure) },
      overall: { score: overallScore, severity: severity(overallScore) }
    };
  }

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
    var items = [
      { title: 'Scripts', body: 'Total: ' + info.scripts.length + '; Inline: ' + (info.inlineScripts || 0) + '; External: ' + (info.externalScripts || (info.scripts.length - (info.inlineScripts || 0))) + '; Third-party: ' + (info.thirdPartyScripts || 0) },
      { title: 'CSP Meta Tags', body: (info.cspMeta && info.cspMeta.length ? 'Present (' + info.cspMeta.length + ')' : 'Missing') },
      { title: 'Inline Event Handlers', body: String(info.inlineEventHandlers || 0) },
      { title: 'Template markers', body: String(info.templateMarkers || 0) },
      { title: 'Token-like strings detected', body: String(info.tokenHits || 0) },
      { title: 'Forms without CSRF tokens', body: String(info.formsWithoutCsrf || 0) + ' of ' + String(info.formsTotal || 0) }
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

  function handleDownload(data, areas) {
    var payload = {
      url: data.url,
      scannedAt: data.ts ? new Date(data.ts).toISOString() : null,
      health: areas.overall,
      areas: areas,
      scripts: data.result.scripts,
      cspMeta: data.result.cspMeta,
      inlineEventHandlers: data.result.inlineEventHandlers,
      templateMarkers: data.result.templateMarkers,
      tokenHits: data.result.tokenHits,
      formsWithoutCsrf: data.result.formsWithoutCsrf,
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
    chrome.storage.local.get(['reviewTargetKey'], function (cfg) {
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
        var areas = entry.areas || computeAreaScores(info);

        setGauge('Overall', areas.overall.score, areas.overall.severity);
        setGauge('Structure', areas.structure.score, areas.structure.severity);
        setGauge('Security', areas.security.score, areas.security.severity);
        setGauge('Exposure', areas.exposure.score, areas.exposure.severity);

        renderFindings(info);

        var dl = document.getElementById('downloadBtn');
        if (dl) {
          dl.addEventListener('click', function () { handleDownload(entry, areas); });
        }
      });
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
