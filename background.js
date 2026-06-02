

const TRUSTED_DOMAINS = [
  "google.com",
  "youtube.com",
  "github.com",
  "microsoft.com",
  "apple.com",
  "paypal.com",
  "facebook.com",
  "instagram.com",
  "amazon.com",
  "chatgpt.com"
];

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".click", ".monster", ".buzz", ".live",
  ".rest", ".fit", ".cam", ".cfd", ".icu", ".tk", ".ml", ".ga"
];

const SCAM_KEYWORDS = [
  "free-robux", "free-vbucks", "claim-reward", "urgent-prize",
  "verify-account", "account-suspended", "login-verification",
  "gift-card-generator", "crypto-scam", "airdrop", "double-your-money",
  "wallet-verify", "seed-phrase", "password-reset-now"
];

const CLICKBAIT_KEYWORDS = [
  "you-wont-believe", "shocking", "secret-method", "make-money-fast",
  "one-weird-trick", "doctors-hate", "limited-time", "act-now"
];

const DARKNET_KEYWORDS = [
  ".onion", "darkweb", "dark-web", "deepweb", "deep-web",
  "tor-market", "hidden-service"
];

const HACK_TOOL_KEYWORDS = [
  "crypter", "stealer", "keylogger", "rat-tool", "password-dump",
  "cookie-logger", "token-grabber", "malware-builder",
  "phishing-kit", "exploit-kit"
];

const DANGEROUS_EXTENSIONS = [
  ".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar",
  ".vbs", ".ps1", ".reg", ".dll", ".iso"
];

const BRAND_TARGETS = [
  { brand: "paypal", real: "paypal.com" },
  { brand: "google", real: "google.com" },
  { brand: "facebook", real: "facebook.com" },
  { brand: "instagram", real: "instagram.com" },
  { brand: "amazon", real: "amazon.com" },
  { brand: "microsoft", real: "microsoft.com" },
  { brand: "apple", real: "apple.com" },
  { brand: "netflix", real: "netflix.com" },
  { brand: "steam", real: "steampowered.com" }
];

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
    scanHistory: []
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "scan-link" && info.linkUrl) {
    const result = scanUrl(info.linkUrl);
    saveScan(info.linkUrl, result);

    chrome.notifications.create({
      type: "basic",
      iconUrl: "icon128.png",
      title: "Scam Link Detector",
      message: `${result.status} - Risk Score: ${result.score}/100`
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
  let category = "General";

  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch {
    return {
      url,
      score: 80,
      status: "Dangerous",
      category: "Invalid URL",
      reasons: ["URL could not be safely read."],
      scannedAt: new Date().toISOString()
    };
  }

  const lowerUrl = url.toLowerCase();
  const hostname = parsedUrl.hostname.toLowerCase();

  if (isTrustedDomain(hostname)) {
    score -= 20;
    reasons.push("Trusted domain detected.");
  }

  if (parsedUrl.protocol === "http:") {
    score += 15;
    reasons.push("Website does not use HTTPS.");
  }

  if (lowerUrl.includes("@")) {
    score += 25;
    reasons.push("URL contains @ symbol, often used to hide redirects.");
  }

  if (url.length > 120) {
    score += 10;
    reasons.push("URL is unusually long.");
  }

  if (hasTooManyHyphens(hostname)) {
    score += 10;
    reasons.push("Domain contains many hyphens.");
  }

  if (isIpAddress(hostname)) {
    score += 25;
    reasons.push("Website uses an IP address instead of a normal domain.");
  }

  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      score += 15;
      reasons.push(`Suspicious domain ending detected: ${tld}`);
    }
  }

  for (const keyword of SCAM_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      score += 22;
      category = "Scam / Phishing";
      reasons.push(`Scam keyword detected: ${keyword}`);
    }
  }

  for (const keyword of CLICKBAIT_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      score += 12;
      category = "Clickbait";
      reasons.push(`Clickbait pattern detected: ${keyword}`);
    }
  }

  for (const keyword of DARKNET_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      score += 30;
      category = "Darknet / Onion Reference";
      reasons.push(`Darknet-related indicator detected: ${keyword}`);
    }
  }

  for (const keyword of HACK_TOOL_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      score += 30;
      category = "Potential Hack Tool / Malware Content";
      reasons.push(`Potential hacking/malware tool indicator: ${keyword}`);
    }
  }

  for (const ext of DANGEROUS_EXTENSIONS) {
    if (lowerUrl.includes(ext)) {
      score += 25;
      category = "Dangerous Download";
      reasons.push(`Dangerous file type detected: ${ext}`);
    }
  }

  const typoResult = detectTyposquatting(hostname);

  if (typoResult.detected) {
    score += 30;
    category = "Typosquatting / Impersonation";
    reasons.push(typoResult.reason);
  }

  score = Math.max(0, Math.min(score, 100));

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
    hostname,
    score,
    status,
    category,
    reasons,
    scannedAt: new Date().toISOString()
  };
}

function isTrustedDomain(hostname) {
  return TRUSTED_DOMAINS.some(domain => {
    return hostname === domain || hostname.endsWith("." + domain);
  });
}

function hasTooManyHyphens(text) {
  const count = (text.match(/-/g) || []).length;
  return count >= 4;
}

function isIpAddress(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function normalizeLookalikes(text) {
  return text
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/\$/g, "s");
}

function detectTyposquatting(hostname) {
  const cleaned = hostname.replace(/^www\./, "");
  const normalized = normalizeLookalikes(cleaned);

  for (const target of BRAND_TARGETS) {
    const brand = target.brand;
    const real = target.real;

    if (cleaned === real || cleaned.endsWith("." + real)) {
      continue;
    }

    if (normalized.includes(brand)) {
      return {
        detected: true,
        reason: `Possible impersonation of ${brand}. Real domain should be ${real}.`
      };
    }
  }

  return {
    detected: false,
    reason: ""
  };
}

function saveScan(url, result) {
  chrome.storage.local.get(["scanHistory"], (data) => {
    const history = data.scanHistory || [];

    history.unshift({
      url,
      hostname: result.hostname || "unknown",
      score: result.score,
      status: result.status,
      category: result.category,
      reasons: result.reasons,
      scannedAt: result.scannedAt
    });

    chrome.storage.local.set({
      scanHistory: history.slice(0, 100)
    });
  });
}
