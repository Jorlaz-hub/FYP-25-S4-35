document.addEventListener('DOMContentLoaded', function () {
  var clearBtn = document.getElementById('clear');
  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      chrome.storage.local.clear(function () {
        var status = document.getElementById('status');
        if (status) status.textContent = 'Storage cleared';
      });
    });
  }
});
