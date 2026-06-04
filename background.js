const API_BASE_URL = "http://localhost:3001";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-link",
    title: "Scan this link with Scam Link Detector",
    contexts: ["link"]
  });

  chrome.storage.local.set({
    protectionEnabled: true,
    aggressiveDetection: true,
    popupProtection: true,
    downloadProtection: true,
    scanHistory: [],
    userReports: [],
    stats: {
      totalScans: 0,
      safeSites: 0,
      suspiciousSites: 0,
      dangerousSites: 0
    }
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "scan-link" && info.linkUrl) {
    scanUrl(info.linkUrl).then((result) => {
      saveScan(info.linkUrl, result);

      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon128.png",
        title: "Scam Link Detector",
        message: `${result.status} - Risk Score: ${result.score}/100`
      });
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_URL") {
    scanUrl(message.url).then((result) => {
      saveScan(message.url, result);
      sendResponse(result);
    });

    return true;
  }

  if (message.type === "REPORT_SITE") {
    saveReport(message).then((result) => {
      sendResponse(result);
    });

    return true;
  }
});

async function scanUrl(url) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/check-url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error("Backend scan failed");
    }

    const data = await response.json();

    if (data.result) {
      return data.result;
    }

    return data;
  } catch (error) {
    return localFallbackScan(url);
  }
}

async function saveReport(report) {
  const localReport = {
    url: report.url,
    title: report.title || "Unknown title",
    reason: report.reason || "No reason provided",
    category: "User Report",
    reportedAt: new Date().toISOString()
  };

  try {
    const response = await fetch(`${API_BASE_URL}/api/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(localReport)
    });

    if (!response.ok) {
      throw new Error("Backend report failed");
    }

    const data = await response.json();

    saveLocalReport(localReport);

    return {
      success: true,
      source: "backend",
      data
    };
  } catch (error) {
    saveLocalReport(localReport);

    return {
      success: true,
      source: "local",
      warning: "Backend unavailable. Report saved locally."
    };
  }
}

function localFallbackScan(url) {
  let score = 0;
  let category = "General";
  const reasons = [];

  const lowerUrl = url.toLowerCase();

  if (lowerUrl.includes("free-robux") || lowerUrl.includes("free-vbucks")) {
    score += 35;
    category = "Gaming Scam";
    reasons.push("Free game currency scam pattern detected.");
  }

  if (lowerUrl.includes("claim") || lowerUrl.includes("reward")) {
    score += 20;
    category = "Scam / Clickbait";
    reasons.push("Reward or claim wording detected.");
  }

  if (lowerUrl.includes(".onion") || lowerUrl.includes("darkweb")) {
    score += 40;
    category = "Darknet Reference";
    reasons.push("Darknet or onion reference detected.");
  }

  if (
    lowerUrl.includes("keylogger") ||
    lowerUrl.includes("token-grabber") ||
    lowerUrl.includes("phishing-kit") ||
    lowerUrl.includes("malware-builder")
  ) {
    score += 45;
    category = "Potential Malware / Hack Tool";
    reasons.push("Potential hacking or malware-tool keyword detected.");
  }

  if (
    lowerUrl.includes(".exe") ||
    lowerUrl.includes(".scr") ||
    lowerUrl.includes(".bat") ||
    lowerUrl.includes(".apk") ||
    lowerUrl.includes(".jar")
  ) {
    score += 30;
    category = "Dangerous Download";
    reasons.push("Dangerous download file type detected.");
  }

  if (lowerUrl.startsWith("http://")) {
    score += 15;
    reasons.push("Website does not use HTTPS.");
  }

  if (lowerUrl.includes("@")) {
    score += 25;
    reasons.push("URL contains @ symbol, often used to hide redirects.");
  }

  score = Math.min(score, 100);

  let status = "Safe";

  if (score >= 70) {
    status = "Dangerous";
  } else if (score >= 35) {
    status = "Suspicious";
  }

  if (reasons.length === 0) {
    reasons.push("No major risk indicators detected.");
  }

  return {
    url,
    score,
    status,
    category,
    reasons,
    scannedAt: new Date().toISOString(),
    source: "local-fallback"
  };
}

function saveScan(url, result) {
  chrome.storage.local.get(["scanHistory", "stats"], (data) => {
    const history = data.scanHistory || [];

    const stats = data.stats || {
      totalScans: 0,
      safeSites: 0,
      suspiciousSites: 0,
      dangerousSites: 0
    };

    history.unshift({
      url,
      hostname: result.hostname || "unknown",
      score: result.score,
      status: result.status,
      category: result.category,
      reasons: result.reasons,
      scannedAt: result.scannedAt,
      source: result.source || "backend"
    });

    stats.totalScans++;

    if (result.status === "Safe") stats.safeSites++;
    if (result.status === "Suspicious") stats.suspiciousSites++;
    if (result.status === "Dangerous") stats.dangerousSites++;

    chrome.storage.local.set({
      scanHistory: history.slice(0, 100),
      stats
    });
  });
}

function saveLocalReport(report) {
  chrome.storage.local.get(["userReports"], (data) => {
    const reports = data.userReports || [];

    reports.unshift(report);

    chrome.storage.local.set({
      userReports: reports.slice(0, 100)
    });
  });
}
