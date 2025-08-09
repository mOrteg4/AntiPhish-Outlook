// This script will handle communication with the backend and other extension logic.

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "checkUrl") {
        fetch("http://localhost:5000/check_url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url: request.url }),
        })
        .then(response => response.text())
        .then(data => {
            console.log("Response from backend:", data);
            sendResponse({data: data});
        })
        .catch(error => {
            console.error("Error:", error);
            sendResponse({data: "Error connecting to the backend."});
        });
        return true; // Indicates that the response is sent asynchronously
    } else if (request.type === "openDashboard") {
        const url = `dashboard.html?url=${encodeURIComponent(request.url)}`;
        chrome.tabs.create({ url: url });
    }
});
