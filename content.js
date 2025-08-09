// This script will be injected into web pages to detect link hovers and display UI.

let statusIcon = null;

document.addEventListener('mouseover', function(e) {
    if (e.target.tagName === 'A') {
        const url = e.target.href;
        chrome.runtime.sendMessage({ type: "checkUrl", url: url }, function(response) {
            if (chrome.runtime.lastError) {
                // Suppress the "Could not establish connection" error
                return;
            }
            if (response && response.data) {
                if (statusIcon) {
                    statusIcon.remove();
                }
                statusIcon = document.createElement('span');
                statusIcon.style.marginLeft = '5px';
                statusIcon.style.padding = '2px 5px';
                statusIcon.style.borderRadius = '5px';

                if (response.data.includes("phishing")) {
                    statusIcon.style.backgroundColor = 'red';
                    statusIcon.textContent = 'X';
                } else {
                    statusIcon.style.backgroundColor = 'green';
                    statusIcon.textContent = '✓';
                }
                e.target.parentNode.insertBefore(statusIcon, e.target.nextSibling);
            }
        });
    }
});

document.addEventListener('mouseout', function(e) {
    if (e.target.tagName === 'A') {
        if (statusIcon) {
            statusIcon.remove();
            statusIcon = null;
        }
    }
});
