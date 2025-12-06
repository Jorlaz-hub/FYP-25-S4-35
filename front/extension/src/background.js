chrome.runtime.onMessage.addListener(function (message, sender) {
  if (message && message.kind === 'pageScanResult') {
    var key = 'scan:' + message.url;
    chrome.storage.local.get(['scanEnabled', key], function (data) {
      if (data.scanEnabled === false) return;
      var list = data[key] || [];
      list.unshift({ ts: Date.now(), result: message });
      var obj = {}; obj[key] = list;
      chrome.storage.local.set(obj);
    });
  }
});

chrome.action.onClicked.addListener(function (tab) {
  if (!tab.id) return;
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ['src/contentScript.js']
  });
});
