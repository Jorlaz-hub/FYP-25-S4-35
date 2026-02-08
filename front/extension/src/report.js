document.addEventListener('DOMContentLoaded', () => {
  const subtitle = document.getElementById('reportSubtitle');
  const summaryGrid = document.getElementById('summaryGrid');
  const scoreTable = document.getElementById('scoreTable');
  const metricList = document.getElementById('metricList');
  const headerList = document.getElementById('headerList');
  const otherList = document.getElementById('otherList');
  const downloadReportBtn = document.getElementById('downloadReportBtn');

  const params = new URLSearchParams(window.location.search);
  const reportId = params.get('id');

  if (!reportId) {
    subtitle.textContent = 'Missing report id.';
    downloadReportBtn.disabled = true;
    return;
  }

  const storageKey = `report:${reportId}`;
  chrome.storage.local.get(storageKey, (data) => {
    const report = data[storageKey];
    if (!report || !report.entry) {
      subtitle.textContent = 'Report data not found.';
      downloadReportBtn.disabled = true;
      return;
    }

    const { site, entry } = report;
    const result = entry.result || {};
    const areas = entry.areas || {};

    const scanTime = entry.ts ? new Date(entry.ts).toLocaleString() : 'Unknown';
    const overallScore = areas.overall?.score ?? '--';
    const overallSeverity = areas.overall?.severity ?? '--';

    subtitle.textContent = `${site || 'Unknown site'} • ${scanTime}`;

    renderSummary(summaryGrid, {
      'Overall Score': `${overallScore} (${overallSeverity})`,
      'URL': result.url || site || 'Unknown',
      'Scan Time': scanTime,
      'Total Scripts': result.scripts?.length ?? '--'
    });

    renderScoreTable(scoreTable, areas);
    renderMetrics(metricList, result);
    renderHeaders(headerList, result);
    renderOtherChecks(otherList, result);

    downloadReportBtn.addEventListener('click', () => {
      const reportText = buildReportText({ site, entry });
      const filename = `scan-report-${new Date().toISOString().slice(0, 10)}.txt`;
      downloadText(reportText, filename);
    });
  });

  function renderSummary(container, items) {
    container.innerHTML = '';
    Object.keys(items).forEach((label) => {
      const value = items[label];
      const item = document.createElement('div');
      item.className = 'summary-item';

      const labelEl = document.createElement('span');
      labelEl.className = 'summary-label';
      labelEl.textContent = label;

      let valueEl;
      if (label === 'URL') {
        item.classList.add('summary-url-item');
        valueEl = document.createElement('div');
        valueEl.className = 'summary-url';

        const urlText = document.createElement('span');
        urlText.className = 'summary-url-text';
        urlText.textContent = value;

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'copy-url-btn';
        copyBtn.title = 'Copy URL';
        copyBtn.setAttribute('aria-label', 'Copy URL');
        copyBtn.textContent = '⧉';
        copyBtn.addEventListener('click', () => {
          copyToClipboard(String(value));
        });

        valueEl.appendChild(urlText);
        item.appendChild(copyBtn);
      } else {
        valueEl = document.createElement('div');
        valueEl.textContent = value;
      }

      item.appendChild(labelEl);
      item.appendChild(valueEl);
      container.appendChild(item);
    });
  }

  function renderScoreTable(table, areas) {
    const rows = [
      { name: 'Structure', data: areas.structure },
      { name: 'Security', data: areas.security },
      { name: 'Exposure', data: areas.exposure },
      { name: 'Overall', data: areas.overall }
    ];

    table.innerHTML = '';

    const headerRow = document.createElement('tr');
    ['Category', 'Score', 'Severity'].forEach((label) => {
      const th = document.createElement('th');
      th.textContent = label;
      headerRow.appendChild(th);
    });
    table.appendChild(headerRow);

    rows.forEach((row) => {
      const tr = document.createElement('tr');
      const scoreVal = row.data?.score ?? '--';
      const severityVal = row.data?.severity ?? '--';

      tr.appendChild(cell(row.name));
      tr.appendChild(cell(scoreVal));
      tr.appendChild(cellBadge(severityVal));
      table.appendChild(tr);
    });
  }

  function renderMetrics(list, result) {
    list.innerHTML = '';
    const inlineScriptsUnsafe = result.inlineScriptsUnsafe ?? '--';
    const thirdPartyUnsafe = result.thirdPartyScriptsUnsafe ?? result.thirdPartyScripts ?? '--';
    const tokenHitsUnsafe = result.tokenHitsUnsafe ?? result.tokenHits ?? '--';
    const templateMarkersUnsafe = result.templateMarkersUnsafe ?? result.templateMarkers ?? '--';
    const formsWithoutCsrfUnsafe = result.formsWithoutCsrfUnsafe ?? result.formsWithoutCsrf ?? '--';
    const metrics = [
      ['Inline scripts without safety tags', inlineScriptsUnsafe],
      ['External scripts without safety checks', thirdPartyUnsafe],
      ['External scripts missing SRI', result.thirdPartyNoSRI ?? '--'],
      ['Clickable elements with inline actions', result.inlineEventHandlers],
      ['Obfuscated inline scripts', result.obfuscatedInlineUnsafe ?? '--'],
      ['Template markers in unsafe scripts', templateMarkersUnsafe],
      ['Token-like strings in unsafe scripts', tokenHitsUnsafe],
      ['Forms missing anti-forgery protection', formsWithoutCsrfUnsafe],
      ['Forms that expose passwords or send data off-site', result.insecureForms],
      ['Number of unsafe links', result.unsafeLinks]
    ];

    metrics.forEach(([label, value]) => {
      list.appendChild(metricItem(label, value));
    });
  }

  function renderHeaders(list, result) {
    list.innerHTML = '';
    const headers = result.responseHeaders || {};
    const cspMeta = result.cspMeta || [];
    const cspVal = (headers['content-security-policy'] || '').toLowerCase();
    const cspTokens = getCspTokens(cspVal);

    list.appendChild(metricItem('Content-Security-Policy header', headers['content-security-policy'] || 'Not present'));
    list.appendChild(metricItem('Strict-Transport-Security', headers['strict-transport-security'] || 'Not present'));
    list.appendChild(metricItem('X-Content-Type-Options', headers['x-content-type-options'] || 'Not present'));
    list.appendChild(metricItem('Referrer-Policy', headers['referrer-policy'] || 'Not present'));
    list.appendChild(metricItem('Permissions-Policy', headers['permissions-policy'] || 'Not present'));
    list.appendChild(metricItem('CSP allows unsafe-inline', cspTokens.hasUnsafeInline ? 'Yes' : cspVal ? 'No' : 'Not present'));
    list.appendChild(metricItem('CSP allows unsafe-eval', cspTokens.hasUnsafeEval ? 'Yes' : cspVal ? 'No' : 'Not present'));
    list.appendChild(metricItem('CSP allows data:', cspTokens.hasData ? 'Yes' : cspVal ? 'No' : 'Not present'));

    if (cspMeta.length > 0) {
      cspMeta.forEach((val, idx) => {
        list.appendChild(metricItem(`CSP meta tag ${idx + 1}`, val));
      });
    } else {
      list.appendChild(metricItem('CSP meta tag', 'Not present'));
    }
  }

  function renderOtherChecks(list, result) {
    list.innerHTML = '';
    const url = result.url || '';
    const isHttps = url ? url.startsWith('https://') : null;
    const cookieIssues = result.cookieIssues || {};
    list.appendChild(metricItem('Page protocol (HTTPS)', isHttps == null ? '--' : (isHttps ? 'Secure (https)' : 'Not secure (http)')));
    list.appendChild(metricItem('Cookies missing HttpOnly', cookieIssues.missingHttpOnly ?? '--'));
    list.appendChild(metricItem('Cookies missing Secure', cookieIssues.missingSecure ?? '--'));
    list.appendChild(metricItem('Cookies missing SameSite', cookieIssues.missingSameSite ?? '--'));
  }

  function getCspTokens(csp) {
    if (!csp) return { hasUnsafeInline: false, hasUnsafeEval: false, hasData: false };
    const tokens = getCspDirectiveTokens(csp, 'script-src')
      .concat(getCspDirectiveTokens(csp, 'script-src-elem'));
    return {
      hasUnsafeInline: tokens.indexOf("'unsafe-inline'") !== -1,
      hasUnsafeEval: tokens.indexOf("'unsafe-eval'") !== -1,
      hasData: tokens.indexOf('data:') !== -1
    };
  }

  function getCspDirectiveTokens(csp, directive) {
    if (!csp) return [];
    const parts = csp.split(';');
    for (let i = 0; i < parts.length; i += 1) {
      const part = parts[i].trim();
      if (!part) continue;
      if (part.indexOf(directive) === 0) {
        const rest = part.slice(directive.length).trim();
        return rest ? rest.split(/\s+/) : [];
      }
    }
    return [];
  }

  function metricItem(label, value) {
    const li = document.createElement('li');
    const text = document.createElement('span');
    text.textContent = `${label}: ${value ?? '--'}`;
    li.appendChild(text);
    return li;
  }

  function cell(text) {
    const td = document.createElement('td');
    td.textContent = text;
    return td;
  }

  function cellBadge(text) {
    const td = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `badge ${String(text).toLowerCase()}`;
    badge.textContent = text;
    td.appendChild(badge);
    return td;
  }

  function buildReportText(report) {
    const { site, entry } = report;
    const result = entry.result || {};
    const areas = entry.areas || {};
    const scanTime = entry.ts ? new Date(entry.ts).toLocaleString() : 'Unknown';

    const lines = [];
    lines.push('Website Safety Report');
    lines.push('-----------');
    lines.push(`Website: ${site || 'Unknown'}`);
    lines.push(`Page: ${result.url || site || 'Unknown'}`);
    lines.push(`Checked on: ${scanTime}`);
    lines.push('');
    lines.push('Overall Results (plain English)');
    lines.push(`Total score: ${areas.overall?.score ?? '--'} (${areas.overall?.severity ?? '--'})`);
    lines.push(`Structure score: ${areas.structure?.score ?? '--'} (${areas.structure?.severity ?? '--'})`);
    lines.push(`Security score: ${areas.security?.score ?? '--'} (${areas.security?.severity ?? '--'})`);
    lines.push(`Exposure score: ${areas.exposure?.score ?? '--'} (${areas.exposure?.severity ?? '--'})`);
    lines.push('');
    lines.push('Key Findings (only unsafe items)');
    lines.push(`Inline scripts without safety tags: ${result.inlineScriptsUnsafe ?? '--'}`);
    lines.push(`External scripts without safety checks: ${result.thirdPartyScriptsUnsafe ?? result.thirdPartyScripts ?? '--'}`);
    lines.push(`External scripts missing SRI: ${result.thirdPartyNoSRI ?? '--'}`);
    lines.push(`Clickable elements with inline actions: ${result.inlineEventHandlers ?? '--'}`);
    lines.push(`Obfuscated inline scripts: ${result.obfuscatedInlineUnsafe ?? '--'}`);
    lines.push(`Template markers in unsafe scripts: ${result.templateMarkersUnsafe ?? result.templateMarkers ?? '--'}`);
    lines.push(`Token-like strings in unsafe scripts: ${result.tokenHitsUnsafe ?? result.tokenHits ?? '--'}`);
    lines.push(`Forms missing anti-forgery protection: ${result.formsWithoutCsrfUnsafe ?? result.formsWithoutCsrf ?? '--'}`);
    lines.push(`Forms that expose passwords or send data off-site: ${result.insecureForms ?? '--'}`);
    lines.push(`Number of unsafe links: ${result.unsafeLinks ?? '--'}`);
    lines.push('');
    lines.push('Security Settings (headers)');
    const headers = result.responseHeaders || {};
    const cspVal = (headers['content-security-policy'] || '').toLowerCase();
    const cspTokens = getCspTokens(cspVal);
    lines.push(`Rules for allowed scripts (CSP): ${headers['content-security-policy'] || 'Not present'}`);
    lines.push(`Force HTTPS (HSTS): ${headers['strict-transport-security'] || 'Not present'}`);
    lines.push(`MIME type protection: ${headers['x-content-type-options'] || 'Not present'}`);
    lines.push(`Referrer privacy setting: ${headers['referrer-policy'] || 'Not present'}`);
    lines.push(`Browser permissions limits: ${headers['permissions-policy'] || 'Not present'}`);
    lines.push(`CSP allows unsafe-inline: ${cspVal ? (cspTokens.hasUnsafeInline ? 'Yes' : 'No') : 'Not present'}`);
    lines.push(`CSP allows unsafe-eval: ${cspVal ? (cspTokens.hasUnsafeEval ? 'Yes' : 'No') : 'Not present'}`);
    lines.push(`CSP allows data: ${cspVal ? (cspTokens.hasData ? 'Yes' : 'No') : 'Not present'}`);
    if (result.cspMeta && result.cspMeta.length > 0) {
      result.cspMeta.forEach((val, idx) => {
        lines.push(`CSP meta tag ${idx + 1}: ${val}`);
      });
    } else {
      lines.push('CSP meta tag: Not present');
    }
    lines.push('');
    lines.push('Protocol & Cookies');
    const url = result.url || '';
    const isHttps = url ? url.startsWith('https://') : null;
    const cookieIssues = result.cookieIssues || {};
    lines.push(`Page protocol (HTTPS): ${isHttps == null ? '--' : (isHttps ? 'Secure (https)' : 'Not secure (http)')}`);
    lines.push(`Cookies missing HttpOnly: ${cookieIssues.missingHttpOnly ?? '--'}`);
    lines.push(`Cookies missing Secure: ${cookieIssues.missingSecure ?? '--'}`);
    lines.push(`Cookies missing SameSite: ${cookieIssues.missingSameSite ?? '--'}`);

    return lines.join('\n');
  }

  function downloadText(text, filename) {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function copyToClipboard(text) {
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).catch(() => {
        fallbackCopy(text);
      });
      return;
    }
    fallbackCopy(text);
  }

  function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
    } catch (err) {
      // No-op if copy fails in restricted contexts.
    }
    document.body.removeChild(textarea);
  }
});
