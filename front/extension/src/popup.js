function formatRow(label, value) {
  var row = document.createElement('div');
  row.className = 'row';
  var l = document.createElement('strong');
  l.textContent = label + ': ';
  var v = document.createElement('span');
  v.textContent = value;
  row.appendChild(l);
  row.appendChild(v);
  return row;
}

function render(results) {
  var container = document.getElementById('results');
  if (!container) return;
  container.innerHTML = '';
  results.slice(0, 20).forEach(function (r) {
    var w = document.createElement('div');
    w.className = 'card';
    var info = r.result;
    w.appendChild(formatRow('URL', info.url));
    w.appendChild(formatRow('Scripts', String(info.scripts.length)));
    w.appendChild(formatRow('CSP Meta Tags', String(info.cspMeta.length)));
    container.appendChild(w);
  });
}

function load() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url) return;
    var key = 'scan:' + tab.url;
    chrome.storage.local.get([key], function (data) {
      render((data || {})[key] || []);
    });
  });
}

document.addEventListener('DOMContentLoaded', load);
