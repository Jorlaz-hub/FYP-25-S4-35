document.addEventListener('DOMContentLoaded', function() {
  // Open repository link
  document.getElementById('repoBtn').addEventListener('click', () => {
    const repoURL = 'https://github.com/Jorlaz-hub/FYP-25-S4-35.git';
    window.open(repoURL, '_blank');
  });

  // Fetch and display all scan history
  document.getElementById('historyBtn').addEventListener('click', () => {
    const container = document.getElementById('historyContainer');
    container.innerHTML = 'Loading history...';

    chrome.storage.local.get(null, (data) => {
      container.innerHTML = ''; // clear loading message

      const scanKeys = Object.keys(data).filter(k => k.startsWith('scan:'));
      if (scanKeys.length === 0) {
        container.textContent = 'No scan history available.';
        return;
      }

      scanKeys.forEach((key) => {
        const historyList = data[key];
        const url = key.replace('scan:', '');

        const title = document.createElement('h3');
        title.textContent = url;
        container.appendChild(title);

        const ul = document.createElement('ul');
        historyList.forEach((entry) => {
          const li = document.createElement('li');
          const date = entry.ts ? new Date(entry.ts).toLocaleString() : 'Unknown';
          const score = entry.areas?.overall?.score ?? '--';
          const severity = entry.areas?.overall?.severity ?? '--';
          li.textContent = `${date} - Score: ${score} (${severity})`;
          ul.appendChild(li);
        });

        container.appendChild(ul);
      });
    });
  });

  document.getElementById('downloadBtn').addEventListener('click', () => {
    chrome.storage.local.get(null, (data) => {
      const scanHistory = {};

      Object.keys(data).forEach((key) => {
        if (key.startsWith('scan:')) {
          scanHistory[key.replace('scan:', '')] = data[key];
        }
      });

      if (Object.keys(scanHistory).length === 0) {
        alert('No scan history available to download.');
        return;
      }

      const json = JSON.stringify(scanHistory, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-history-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();

      URL.revokeObjectURL(url);
    });
  });
});
