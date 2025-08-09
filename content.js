// This script will be injected into web pages to detect link hovers and display UI.

let popup = null;
let hoverTimeout = null;
let mouseoutTimeout = null;

function showPopup(e) {
    // Clear any existing timeouts
    if (mouseoutTimeout) {
        clearTimeout(mouseoutTimeout);
        mouseoutTimeout = null;
    }

    // Don't show popup if one is already visible
    if (popup) {
        return;
    }

    hoverTimeout = setTimeout(() => {
        popup = document.createElement('div');
        popup.id = 'phishing-popup';
        popup.innerHTML = `
            <div class="status">Analyzing...</div>
            <button id="take-me-there">Take me there</button>
            <button id="check-in-dashboard">Check in Dashboard</button>
        `;

        const rect = e.target.getBoundingClientRect();
        document.body.appendChild(popup);
        popup.style.left = `${rect.left + window.scrollX}px`;
        popup.style.top = `${rect.bottom + window.scrollY + 5}px`;
        popup.dataset.url = e.target.href;

        const url = e.target.href;
        chrome.runtime.sendMessage({ type: "checkUrl", url: url }, function(response) {
            if (chrome.runtime.lastError) { return; }
            if (response && response.data && popup) {
                const statusDiv = popup.querySelector('.status');
                if (response.data.includes("phishing")) {
                    statusDiv.textContent = '⚠️ Potentially Malicious';
                    statusDiv.style.color = 'red';
                } else {
                    statusDiv.textContent = '✅ Safe';
                    statusDiv.style.color = 'green';
                }
            }
        });

    }, 200); // 200ms delay before showing popup
}

function hidePopup() {
    if (hoverTimeout) {
        clearTimeout(hoverTimeout);
        hoverTimeout = null;
    }
    mouseoutTimeout = setTimeout(() => {
        if (popup) {
            popup.remove();
            popup = null;
        }
    }, 300); // 300ms delay before hiding popup
}

document.addEventListener('mouseover', function(e) {
    if (e.target.tagName === 'A') {
        showPopup(e);
    }
});

document.addEventListener('mouseout', function(e) {
    if (e.target.tagName === 'A') {
        hidePopup();
    }
});

document.addEventListener('click', function(e) {
    if (e.target.id === 'check-in-dashboard') {
        const url = popup.dataset.url;
        chrome.runtime.sendMessage({ type: "openDashboard", url: url });
        hidePopup();
    } else if (e.target.id === 'take-me-there') {
        const url = popup.dataset.url;
        sessionStorage.setItem(`safe_url_${url}`, 'true');
        hidePopup();
    }
});
