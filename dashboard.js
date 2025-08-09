document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const checkUrlButton = document.getElementById('check-url-button');
    const statusMessage = document.getElementById('status-message');

    // Function to check a URL
    async function checkUrl(url) {
        statusMessage.textContent = 'Analyzing...';
        try {
            const response = await fetch("http://localhost:5000/check_url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url: url }),
            });
            const responseText = await response.text();
            statusMessage.textContent = responseText;
        } catch (error) {
            console.error("Error:", error);
            statusMessage.textContent = "Error connecting to the backend.";
        }
    }

    // Check for a URL in the query string when the page loads
    const params = new URLSearchParams(window.location.search);
    const urlFromQuery = params.get('url');
    if (urlFromQuery) {
        urlInput.value = urlFromQuery;
        checkUrl(urlFromQuery);
    }

    // Add click listener for the button
    checkUrlButton.addEventListener('click', () => {
        const url = urlInput.value;
        if (url) {
            checkUrl(url);
        }
    });
});