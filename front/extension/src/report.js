document.addEventListener('DOMContentLoaded', () => {
  const subtitle = document.getElementById('reportSubtitle');
  const summaryGrid = document.getElementById('summaryGrid');
  const scoreTable = document.getElementById('scoreTable');
  const metricList = document.getElementById('metricList');
  const headerList = document.getElementById('headerList');
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

      const valueEl = document.createElement('div');
      valueEl.textContent = value;

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
    const metrics = [
      ['Inline scripts', result.inlineScripts],
      ['External scripts', result.externalScripts],
      ['Third-party scripts', result.thirdPartyScripts],
      ['Inline event handlers', result.inlineEventHandlers],
      ['Template markers', result.templateMarkers],
      ['Token hits', result.tokenHits],
      ['Forms detected', result.formsTotal],
      ['Forms without CSRF', result.formsWithoutCsrf],
      ['Insecure forms', result.insecureForms],
      ['Unsafe links', result.unsafeLinks]
    ];

    metrics.forEach(([label, value]) => {
      list.appendChild(metricItem(label, value));
    });
  }

  function renderHeaders(list, result) {
    list.innerHTML = '';
    const headers = result.responseHeaders || {};
    const cspMeta = result.cspMeta || [];

    list.appendChild(metricItem('Content-Security-Policy header', headers['content-security-policy'] || 'Not present'));
    list.appendChild(metricItem('Strict-Transport-Security', headers['strict-transport-security'] || 'Not present'));
    list.appendChild(metricItem('X-Content-Type-Options', headers['x-content-type-options'] || 'Not present'));
    list.appendChild(metricItem('Referrer-Policy', headers['referrer-policy'] || 'Not present'));
    list.appendChild(metricItem('Permissions-Policy', headers['permissions-policy'] || 'Not present'));

    if (cspMeta.length > 0) {
      cspMeta.forEach((val, idx) => {
        list.appendChild(metricItem(`CSP meta tag ${idx + 1}`, val));
      });
    } else {
      list.appendChild(metricItem('CSP meta tag', 'Not present'));
    }
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
    lines.push('Scan Report');
    lines.push('-----------');
    lines.push(`Site: ${site || 'Unknown'}`);
    lines.push(`URL: ${result.url || site || 'Unknown'}`);
    lines.push(`Scan Time: ${scanTime}`);
    lines.push('');
    lines.push('Score Breakdown');
    lines.push(`Structure: ${areas.structure?.score ?? '--'} (${areas.structure?.severity ?? '--'})`);
    lines.push(`Security: ${areas.security?.score ?? '--'} (${areas.security?.severity ?? '--'})`);
    lines.push(`Exposure: ${areas.exposure?.score ?? '--'} (${areas.exposure?.severity ?? '--'})`);
    lines.push(`Overall: ${areas.overall?.score ?? '--'} (${areas.overall?.severity ?? '--'})`);
    lines.push('');
    lines.push('Key Metrics');
    lines.push(`Inline scripts: ${result.inlineScripts ?? '--'}`);
    lines.push(`External scripts: ${result.externalScripts ?? '--'}`);
    lines.push(`Third-party scripts: ${result.thirdPartyScripts ?? '--'}`);
    lines.push(`Inline event handlers: ${result.inlineEventHandlers ?? '--'}`);
    lines.push(`Template markers: ${result.templateMarkers ?? '--'}`);
    lines.push(`Token hits: ${result.tokenHits ?? '--'}`);
    lines.push(`Forms detected: ${result.formsTotal ?? '--'}`);
    lines.push(`Forms without CSRF: ${result.formsWithoutCsrf ?? '--'}`);
    lines.push(`Insecure forms: ${result.insecureForms ?? '--'}`);
    lines.push(`Unsafe links: ${result.unsafeLinks ?? '--'}`);
    lines.push('');
    lines.push('Headers & CSP');
    const headers = result.responseHeaders || {};
    lines.push(`Content-Security-Policy header: ${headers['content-security-policy'] || 'Not present'}`);
    lines.push(`Strict-Transport-Security: ${headers['strict-transport-security'] || 'Not present'}`);
    lines.push(`X-Content-Type-Options: ${headers['x-content-type-options'] || 'Not present'}`);
    lines.push(`Referrer-Policy: ${headers['referrer-policy'] || 'Not present'}`);
    lines.push(`Permissions-Policy: ${headers['permissions-policy'] || 'Not present'}`);
    if (result.cspMeta && result.cspMeta.length > 0) {
      result.cspMeta.forEach((val, idx) => {
        lines.push(`CSP meta tag ${idx + 1}: ${val}`);
      });
    } else {
      lines.push('CSP meta tag: Not present');
    }

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
});
