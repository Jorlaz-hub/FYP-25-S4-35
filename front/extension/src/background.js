// Background service worker sits outside page context.
// It can perform network requests with broader permissions (via host_permissions)
// and persist results using chrome.storage or trigger downloads.
// WIP

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  // Store page scan results under a URL-scoped key for later inspection.
  if (message && message.kind === 'pageScanResult') {
    var key = 'scan:' + message.url;
    chrome.storage.local.get([key], function (data) {
      var list = data[key] || [];
      list.unshift({ ts: Date.now(), result: message });
      var obj = {}; obj[key] = list;
      chrome.storage.local.set(obj);
    });
  }

  // Fetch external script content when the content script is blocked by CORS.
  if (message && message.kind === 'fetchScriptInBackground' && typeof message.url === 'string') {
    (async function () {
      try {
        // credentials: 'omit' to avoid mixing cookies; adjust if needed
        var res = await fetch(message.url, { credentials: 'omit' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        var text = await res.text();
        sendResponse({ ok: true, content: text });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
    })();
    return true; // Keep the message channel open for async sendResponse
  }
});

// Optional: allow clicking the extension icon to inject the content script.
chrome.action.onClicked.addListener(function (tab) {
  if (!tab.id) return;
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ['src/contentScript.js']
  });
});

// Reflect toggle state via badge and gate auto behavior.
// This helps users see if inspection is enabled even when popup is closed.
(function initBadgeAndBehavior() {
  // Set initial badge at startup and install
  var setFromStorage = function () {
    chrome.storage.local.get(['inspectEnabled'], function (obj) {
      var enabled = !!obj.inspectEnabled;
      chrome.action.setBadgeText({ text: enabled ? 'ON' : '' });
      chrome.action.setBadgeBackgroundColor({ color: enabled ? '#2e7d32' : '#00000000' });
    });
  };

  if (chrome.runtime.onStartup) {
    chrome.runtime.onStartup.addListener(setFromStorage);
  }
  if (chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(setFromStorage);
  }
  setFromStorage();

  // Update badge when toggle changes
  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area !== 'local' || !changes.inspectEnabled) return;
    var enabled = !!changes.inspectEnabled.newValue;
    chrome.action.setBadgeText({ text: enabled ? 'ON' : '' });
    chrome.action.setBadgeBackgroundColor({ color: enabled ? '#2e7d32' : '#00000000' });
  });
})();
