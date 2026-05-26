// Scam Link Detector - background.js

const SCAM_KEYWORDS = [
  "free-robux",
  "free-vbucks",
  "claim-reward",
  "urgent-prize",
  "verify-account-now",
  "crypto-scam",
  "malware-download",
  "phishing-login",
  "steam-gift-card",
  "gift-card-generator",
  "account-suspended",
  "login-verification"
];

const DANGEROUS_EXTENSIONS = [
  ".exe",
  ".scr",
  ".bat",
  ".cmd",
  ".msi",
  ".apk",
  ".jar",
  ".zip"
];

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-link",
    title: "Scan this link with Scam Link Detector",
    contexts: ["link"]
  });

  chrome.storage.local.set({
    protectionEnabled: true,
    scanHistory: []
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "scan-link" && info.linkUrl) {
    const result = scanUrl(info.linkUrl);
    saveScan(info.linkUrl, result);

    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "Scam Link Detector",
      message: `Risk Score: ${result.score}/100 - ${result.status}`
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_URL") {
    const result = scanUrl(message.url);
    saveScan(message.url, result);
    sendResponse(result);
  }

  return true;
});

function scanUrl(url) {
  let score = 0;
  const reasons = [];

  const lowerUrl = url.toLowerCase();

  for (const keyword of SCAM_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      score += 20;
      reasons.push(`Suspicious keyword found: ${keyword}`);
    }
  }

  for (const ext of DANGEROUS_EXTENSIONS) {
    if (lowerUrl.includes(ext)) {
      score += 25;
      reasons.push(`Dangerous file type detected: ${ext}`);
    }
  }

  if (lowerUrl.startsWith("http://")) {
    score += 15;
    reasons.push("Website does not use HTTPS");
  }

  if (lowerUrl.includes("@")) {
    score += 20;
    reasons.push("URL contains @ symbol, which can hide the real destination");
  }

  if (lowerUrl.length > 120) {
    score += 10;
    reasons.push("URL is unusually long");
  }

  if (hasTooManyHyphens(lowerUrl)) {
    score += 10;
    reasons.push("URL contains many hyphens");
  }

  if (isLikelyIpAddress(lowerUrl)) {
    score += 25;
    reasons.push("URL uses an IP address instead of a normal domain");
  }

  score = Math.min(score, 100);

  let status = "Safe";

  if (score >= 70) {
    status = "Dangerous";
  } else if (score >= 35) {
    status = "Suspicious";
  }

  return {
    url,
    score,
    status,
    reasons,
    scannedAt: new Date().toISOString()
  };
}

function hasTooManyHyphens(url) {
  const count = (url.match(/-/g) || []).length;
  return count >= 5;
}

function isLikelyIpAddress(url) {
  return /https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(url);
}

function saveScan(url, result) {
  chrome.storage.local.get(["scanHistory"], (data) => {
    const history = data.scanHistory || [];

    history.unshift({
      url,
      score: result.score,
      status: result.status,
      reasons: result.reasons,
      scannedAt: result.scannedAt
    });

    const trimmedHistory = history.slice(0, 50);

    chrome.storage.local.set({
      scanHistory: trimmedHistory
    });
  });
}
