// Scam Link Detector - popup.js

document.addEventListener("DOMContentLoaded", () => {
  const scanButton = document.getElementById("scan-button");
  const riskScore = document.getElementById("risk-score");
  const riskStatus = document.getElementById("risk-status");
  const reasonsContainer = document.getElementById("reasons-container");
  const historyList = document.getElementById("history-list");
  const protectionStatus = document.getElementById("protection-status");

  loadProtectionStatus();
  loadHistory();

  scanButton.addEventListener("click", async () => {
    reasonsContainer.innerHTML = "";

    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    if (!tab || !tab.url) {
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: "SCAN_URL",
        url: tab.url
      },
      (response) => {
        if (!response) return;

        updateResults(response);
        loadHistory();
      }
    );
  });

  function updateResults(result) {
    riskScore.textContent = result.score;
    riskStatus.textContent = result.status;

    if (result.status === "Dangerous") {
      riskStatus.style.color = "red";
    } else if (result.status === "Suspicious") {
      riskStatus.style.color = "orange";
    } else {
      riskStatus.style.color = "limegreen";
    }

    reasonsContainer.innerHTML = "";

    if (result.reasons.length === 0) {
      reasonsContainer.innerHTML = `
        <p>No suspicious indicators detected.</p>
      `;
      return;
    }

    result.reasons.forEach((reason) => {
      const reasonItem = document.createElement("p");
      reasonItem.textContent = `⚠ ${reason}`;
      reasonsContainer.appendChild(reasonItem);
    });
  }

  function loadHistory() {
    chrome.storage.local.get(["scanHistory"], (data) => {
      historyList.innerHTML = "";

      const history = data.scanHistory || [];

      if (history.length === 0) {
        historyList.innerHTML = `
          <li>No scans yet.</li>
        `;
        return;
      }

      history.slice(0, 5).forEach((item) => {
        const li = document.createElement("li");

        li.innerHTML = `
          <strong>${item.status}</strong>
          (${item.score}/100)
          <br>
          <small>${truncateUrl(item.url)}</small>
        `;

        if (item.status === "Dangerous") {
          li.style.borderLeft = "4px solid red";
        } else if (item.status === "Suspicious") {
          li.style.borderLeft = "4px solid orange";
        } else {
          li.style.borderLeft = "4px solid limegreen";
        }

        historyList.appendChild(li);
      });
    });
  }

  function loadProtectionStatus() {
    chrome.storage.local.get(
      ["protectionEnabled"],
      (data) => {
        const enabled =
          data.protectionEnabled !== false;

        protectionStatus.textContent =
          enabled ? "Active" : "Disabled";

        protectionStatus.style.color =
          enabled ? "limegreen" : "red";
      }
    );
  }

  function truncateUrl(url) {
    if (url.length > 45) {
      return url.substring(0, 45) + "...";
    }

    return url;
  }
});
