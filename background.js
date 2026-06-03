// same upgraded background engine, now with report system

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["userReports"], (data) => {
    chrome.storage.local.set({
      protectionEnabled: true,
      aggressiveDetection: true,
      popupProtection: true,
      downloadProtection: true,
      scanHistory: [],
      userReports: data.userReports || [],
      stats: {
        totalScans: 0,
        safeSites: 0,
        suspiciousSites: 0,
        dangerousSites: 0
      }
    });
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_URL") {
    const result = scanUrl(message.url);
    saveScan(message.url, result);
    sendResponse(result);
    return true;
  }

  if (message.type === "REPORT_SITE") {
    saveReport(message);
    sendResponse({ success: true });
    return true;
  }
});

function scanUrl(url) {
  let score = 0;
  const reasons = [];
  let category = "General";

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

  if (score >= 70) status = "Dangerous";
  else if (score >= 35) status = "Suspicious";

  if (reasons.length === 0) {
    reasons.push("No major risk indicators detected.");
  }

  return {
    url,
    score,
    status,
    category,
    reasons,
    scannedAt: new Date().toISOString()
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
      score: result.score,
      status: result.status,
      category: result.category,
      reasons: result.reasons,
      scannedAt: result.scannedAt
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

function saveReport(report) {
  chrome.storage.local.get(["userReports"], (data) => {
    const reports = data.userReports || [];

    reports.unshift({
      url: report.url,
      title: report.title,
      reason: report.reason,
      reportedAt: new Date().toISOString()
    });

    chrome.storage.local.set({
      userReports: reports.slice(0, 100)
    });
  });
}
