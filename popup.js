document.addEventListener("DOMContentLoaded", () => {
  const scanButton = document.getElementById("scan-button");
  const reportButton = document.getElementById("report-button");
  const openOptionsButton = document.getElementById("open-options");

  const riskScore = document.getElementById("risk-score");
  const riskStatus = document.getElementById("risk-status");
  const riskCategory = document.getElementById("risk-category");
  const scannedUrl = document.getElementById("scanned-url");
  const reasonsContainer = document.getElementById("reasons-container");
  const historyList = document.getElementById("history-list");
  const protectionStatus = document.getElementById("protection-status");

  const totalScans = document.getElementById("total-scans");
  const safeSites = document.getElementById("safe-sites");
  const suspiciousSites = document.getElementById("suspicious-sites");
  const dangerousSites = document.getElementById("dangerous-sites");
  const userReports = document.getElementById("user-reports");

  loadProtectionStatus();
  loadHistory();
  loadStats();

  scanButton.addEventListener("click", scanCurrentTab);
  reportButton.addEventListener("click", reportCurrentTab);

  openOptionsButton.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  async function scanCurrentTab() {
    reasonsContainer.innerHTML = "<p>Scanning website...</p>";

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
      reasonsContainer.innerHTML = "<p>Could not read this tab.</p>";
      return;
    }

    chrome.runtime.sendMessage({ type: "SCAN_URL", url: tab.url }, (response) => {
      if (!response) {
        reasonsContainer.innerHTML = "<p>No scan response received.</p>";
        return;
      }

      updateResults(response);
      loadHistory();
      loadStats();
    });
  }

  async function reportCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
      alert("Could not read this website.");
      return;
    }

    const reason = prompt(
      "Why are you reporting this site?\n\nExamples: scam, phishing, clickbait, fake download, dark web reference, hack tool content"
    );

    if (!reason) return;

    chrome.runtime.sendMessage(
      {
        type: "REPORT_SITE",
        url: tab.url,
        title: tab.title || "Unknown title",
        reason
      },
      (response) => {
        if (response && response.success) {
          alert("Report saved successfully.");
          loadStats();
          loadHistory();
        } else {
          alert("Report could not be saved.");
        }
      }
    );
  }

  function updateResults(result) {
    scannedUrl.textContent = truncateUrl(result.url || "Unknown URL", 70);
    riskScore.textContent = result.score;
    riskStatus.textContent = result.status;
    riskCategory.textContent = result.category || "General";

    riskStatus.style.color =
      result.status === "Dangerous" ? "#ff2f00" :
      result.status === "Suspicious" ? "#ff6a00" :
      "#168a3a";

    reasonsContainer.innerHTML = "";

    if (!result.reasons || result.reasons.length === 0) {
      reasonsContainer.innerHTML = "<p>No suspicious indicators detected.</p>";
      return;
    }

    result.reasons.forEach((reason) => {
      const item = document.createElement("p");
      item.textContent = `• ${reason}`;
      reasonsContainer.appendChild(item);
    });
  }

  function loadHistory() {
    chrome.storage.local.get(["scanHistory", "userReports"], (data) => {
      historyList.innerHTML = "";

      const history = data.scanHistory || [];
      const reports = data.userReports || [];

      const combined = [
        ...reports.map(report => ({
          type: "Report",
          status: "Reported",
          score: "User",
          category: report.reason,
          url: report.url,
          scannedAt: report.reportedAt
        })),
        ...history.map(scan => ({
          type: "Scan",
          ...scan
        }))
      ].sort((a, b) => new Date(b.scannedAt || b.reportedAt) - new Date(a.scannedAt || a.reportedAt));

      if (combined.length === 0) {
        historyList.innerHTML = "<li>No activity yet.</li>";
        return;
      }

      combined.slice(0, 6).forEach((item) => {
        const li = document.createElement("li");

        li.innerHTML = `
          <strong>${item.type || "Scan"}: ${item.status}</strong>
          <br>
          <small>${item.category || "General"}</small>
          <br>
          <small>${truncateUrl(item.url, 48)}</small>
        `;

        li.style.borderLeft =
          item.type === "Report" ? "5px solid #ff6a00" :
          item.status === "Dangerous" ? "5px solid #ff2f00" :
          item.status === "Suspicious" ? "5px solid #ff6a00" :
          "5px solid #168a3a";

        historyList.appendChild(li);
      });
    });
  }

  function loadStats() {
    chrome.storage.local.get(["stats", "userReports"], (data) => {
      const stats = data.stats || {
        totalScans: 0,
        safeSites: 0,
        suspiciousSites: 0,
        dangerousSites: 0
      };

      const reports = data.userReports || [];

      totalScans.textContent = stats.totalScans;
      safeSites.textContent = stats.safeSites;
      suspiciousSites.textContent = stats.suspiciousSites;
      dangerousSites.textContent = stats.dangerousSites;
      userReports.textContent = reports.length;
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
    return url.length > maxLength ? url.substring(0, maxLength) + "..." : url;
  }
});
