

document.addEventListener("DOMContentLoaded", () => {
  const scanButton = document.getElementById("scan-button");
  const openOptionsButton = document.getElementById("open-options");

  const riskScore = document.getElementById("risk-score");
  const riskStatus = document.getElementById("risk-status");
  const riskCategory = document.getElementById("risk-category");
  const scannedUrl = document.getElementById("scanned-url");

  const reasonsContainer = document.getElementById("reasons-container");
  const historyList = document.getElementById("history-list");
  const protectionStatus = document.getElementById("protection-status");

  loadProtectionStatus();
  loadHistory();

  scanButton.addEventListener("click", scanCurrentTab);

  openOptionsButton.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  async function scanCurrentTab() {
    reasonsContainer.innerHTML = "<p>Scanning website...</p>";

    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    if (!tab || !tab.url) {
      reasonsContainer.innerHTML = "<p>Could not read this tab.</p>";
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: "SCAN_URL",
        url: tab.url
      },
      (response) => {
        if (!response) {
          reasonsContainer.innerHTML = "<p>No scan response received.</p>";
          return;
        }

        updateResults(response);
        loadHistory();
      }
    );
  }

  function updateResults(result) {
    scannedUrl.textContent = truncateUrl(result.url || "Unknown URL", 70);
    riskScore.textContent = result.score;
    riskStatus.textContent = result.status;
    riskCategory.textContent = result.category || "General";

    riskStatus.className = "";

    if (result.status === "Dangerous") {
      riskStatus.style.color = "#ff2f00";
    } else if (result.status === "Suspicious") {
      riskStatus.style.color = "#ff6a00";
    } else {
      riskStatus.style.color = "#168a3a";
    }

    reasonsContainer.innerHTML = "";

    if (!result.reasons || result.reasons.length === 0) {
      reasonsContainer.innerHTML = "<p>No suspicious indicators detected.</p>";
      return;
    }

    result.reasons.forEach((reason) => {
      const reasonItem = document.createElement("p");
      reasonItem.textContent = `• ${reason}`;
      reasonsContainer.appendChild(reasonItem);
    });
  }

  function loadHistory() {
    chrome.storage.local.get(["scanHistory"], (data) => {
      historyList.innerHTML = "";

      const history = data.scanHistory || [];

      if (history.length === 0) {
        historyList.innerHTML = "<li>No scans yet.</li>";
        return;
      }

      history.slice(0, 6).forEach((item) => {
        const li = document.createElement("li");

        li.innerHTML = `
          <strong>${item.status}</strong> 
          <span>(${item.score}/100)</span>
          <br>
          <small>${item.category || "General"}</small>
          <br>
          <small>${truncateUrl(item.url, 48)}</small>
        `;

        if (item.status === "Dangerous") {
          li.style.borderLeft = "5px solid #ff2f00";
        } else if (item.status === "Suspicious") {
          li.style.borderLeft = "5px solid #ff6a00";
        } else {
          li.style.borderLeft = "5px solid #168a3a";
        }

        historyList.appendChild(li);
      });
    });
  }

  function loadProtectionStatus() {
    chrome.storage.local.get(["protectionEnabled"], (data) => {
      const enabled = data.protectionEnabled !== false;

      protectionStatus.textContent = enabled
        ? "Real-time protection is active"
        : "Real-time protection is disabled";

      protectionStatus.style.color = enabled ? "#168a3a" : "#ff2f00";
      protectionStatus.style.fontWeight = "bold";
    });
  }

  function truncateUrl(url, maxLength) {
    if (!url) return "Unknown URL";

    if (url.length > maxLength) {
      return url.substring(0, maxLength) + "...";
    }

    return url;
  }
});
