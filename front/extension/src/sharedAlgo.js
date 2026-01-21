var SharedAlgo = (function () {
  function clamp(n, min, max) {
    return Math.max(min, Math.min(max, n));
  }

  function severity(val) {
    return val < 40 ? 'unsafe' : val <= 75 ? 'poor' : 'passed';
  }

  var DEFAULT_CHECKS = {
    https: true,
    csp: true,
    cspQuality: true,
    hsts: true,
    xcto: true,
    referrer: true,
    permissions: true,
    thirdParty: true,
    sri: true,
    inlineScripts: true,
    inlineEvents: true,
    templateMarkers: true,
    obfuscated: true,
    unsafeLinks: true,
    csrf: true,
    insecureForms: true,
    tokenHits: true,
    cookie: true
  };

  function normalizeChecks(raw) {
    var out = {};
    Object.keys(DEFAULT_CHECKS).forEach(function (key) {
      out[key] = raw && typeof raw[key] === 'boolean' ? raw[key] : DEFAULT_CHECKS[key];
    });
    return out;
  }

  function computeAreaScores(info, checksRaw) {
    if (!info || !info.scripts) {
      return {
        structure: { score: 0, severity: 'ready' },
        security: { score: 0, severity: 'ready' },
        exposure: { score: 0, severity: 'ready' },
        overall: { score: 0, severity: 'ready' }
      };
    }

    var checks = normalizeChecks(checksRaw);
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
    var headers = info.responseHeaders || {};
    var hdrs = {};
    Object.keys(headers).forEach(function (k) { hdrs[k.toLowerCase()] = headers[k]; });
    var cookieIssues = info.cookieIssues || { missingHttpOnly: 0, missingSecure: 0, missingSameSite: 0 };

    var hasCspHeader = !!hdrs['content-security-policy'];
    var noCsp = !hasCspHeader && (info.cspMeta || []).length === 0;
    var inlineEvents = info.inlineEventHandlers || 0;
    var templateMarkers = info.templateMarkers || 0;
    var tokenHits = info.tokenHits || 0;
    var formsWithoutCsrf = info.formsWithoutCsrf || 0;

    var structure = 100;
    if (checks.inlineScripts) structure -= clamp(inlineCount * 3, 0, 25);
    if (checks.inlineEvents) structure -= clamp(inlineEvents * 2, 0, 20);
    if (checks.templateMarkers) structure -= clamp(templateMarkers * 3, 0, 15);
    if (checks.unsafeLinks) structure -= clamp((info.unsafeLinks || 0) * 2, 0, 10);

    var security = 100;
    if (checks.csp && noCsp) {
      security -= 15;
    } else if (checks.cspQuality) {
      var cspVal = (hdrs['content-security-policy'] || '').toLowerCase();
      if (cspVal.indexOf("'unsafe-inline'") !== -1) security -= 10;
      if (cspVal.indexOf("'unsafe-eval'") !== -1) security -= 5;
      if (cspVal.indexOf("data:") !== -1) security -= 3;
    }
    if (checks.hsts && !hdrs['strict-transport-security']) security -= 8;
    if (checks.xcto && !hdrs['x-content-type-options']) security -= 6;
    if (checks.referrer && !hdrs['referrer-policy']) security -= 4;
    if (checks.permissions && !hdrs['permissions-policy']) security -= 4;
    if (checks.sri) security -= clamp(noIntegrity * 2, 0, 16);
    if (checks.thirdParty) security -= clamp(thirdParty * 2, 0, 16);
    if (checks.inlineScripts) security -= clamp(inlineCount * 1.5, 0, 15);
    try {
      if (checks.https && new URL(info.url).protocol !== 'https:') security -= 10;
    } catch (e) {}

    if (checks.obfuscated) {
      var obfuscatedCount = info.scripts.filter(function (s) { return s.isObfuscated; }).length;
      if (obfuscatedCount > 0) {
        security -= (obfuscatedCount * 10);
      }
    }

    if (checks.cookie) {
      security -= clamp(cookieIssues.missingHttpOnly * 5, 0, 15);
      security -= clamp(cookieIssues.missingSecure * 4, 0, 12);
      security -= clamp(cookieIssues.missingSameSite * 2, 0, 8);
    }

    var exposure = 100;
    if (checks.csrf) exposure -= clamp(formsWithoutCsrf * 5, 0, 25);
    if (checks.tokenHits) exposure -= clamp(tokenHits * 4, 0, 20);
    if (checks.thirdParty) exposure -= clamp(thirdParty * 2, 0, 20);
    if (checks.inlineScripts) exposure -= clamp(inlineCount * 1, 0, 10);
    if (checks.insecureForms) exposure -= clamp((info.insecureForms || 0) * 10, 0, 20);

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

  return {
    DEFAULT_CHECKS: DEFAULT_CHECKS,
    normalizeChecks: normalizeChecks,
    computeAreaScores: computeAreaScores
  };
})();
