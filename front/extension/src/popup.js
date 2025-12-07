// Formats a single row of label and value
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

// Renders the scan results into the popup
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

// Loads the scan results for the current tab
function load() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url) return;
    var key = 'scan:' + tab.url;
    // utilises chrome.storage.local to get the scan results
    chrome.storage.local.get([key], function (data) {
      render((data || {})[key] || []);
    });
  });
}

// Adds an event listener to load the scan results when the popup is loaded
// Persist and restore the Inspect toggle so popup state survives close/open.
document.addEventListener('DOMContentLoaded', function () {
  load(); // render recent scans

  var toggle = document.getElementById('inspectToggle');
  if (!toggle) return; // safe if toggle not present yet

  // Restore state on popup open
  chrome.storage.local.get(['inspectEnabled'], function (obj) {
    toggle.checked = !!obj.inspectEnabled;
  });

  // Persist on change
  toggle.addEventListener('change', function () {
    chrome.storage.local.set({ inspectEnabled: toggle.checked });
  });
});
