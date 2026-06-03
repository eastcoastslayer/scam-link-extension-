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
  "chatgpt.com",
  "openai.com"
];

const SUSPICIOUS_TLDS = [
  ".xyz",
  ".top",
  ".click",
  ".monster",
  ".buzz",
  ".live",
  ".cam",
  ".cfd",
  ".icu",
  ".tk",
  ".ml",
  ".ga"
];

const SCAM_KEYWORDS = [
  "free-robux",
  "free-vbucks",
  "claim-reward",
  "urgent-prize",
  "verify-account",
  "account-suspended",
  "gift-card-generator",
  "wallet-verify",
  "seed-phrase",
  "password-reset-now",
  "login-verification"
];

const CLICKBAIT_KEYWORDS = [
  "you-wont-believe",
  "shocking",
  "secret-method",
  "make-money-fast",
  "one-weird-trick",
  "limited-time",
  "act-now",
  "doctors-hate"
];

const DARKNET_KEYWORDS = [
  ".onion",
  "darkweb",
  "dark-web",
  "deepweb",
  "deep-web",
  "tor-market",
  "hidden-service"
];

const HACK_TOOL_KEYWORDS = [
  "keylogger",
  "token-grabber",
  "cookie-logger",
  "phishing-kit",
  "malware-builder",
  "crypter",
  "stealer",
  "rat-tool",
  "password-dump",
  "exploit-kit"
];

const DANGEROUS_EXTENSIONS = [
  ".exe",
  ".scr",
  ".bat",
  ".cmd",
  ".msi",
  ".apk",
  ".jar",
  ".vbs",
  ".ps1",
  ".reg",
  ".dll",
  ".iso"
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

function scanUrl(url) {
  let score = 0;
  const reasons = [];
  let category = "General";

  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch {
    return buildResult(url, "unknown", 80, "Dangerous", "Invalid URL", [
      "URL could not be safely read."
    ]);
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
      reasons.push(`Potential hacking or malware indicator: ${keyword}`);
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

  return buildResult(url, hostname, score, status, category, reasons);
}

function buildResult(url, hostname, score, status, category, reasons) {
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
  return TRUSTED_DOMAINS.some((domain) => {
    return hostname === domain || hostname.endsWith("." + domain);
  });
}

function hasTooManyHyphens(text) {
  return (text.match(/-/g) || []).length >= 4;
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
    if (cleaned === target.real || cleaned.endsWith("." + target.real)) {
      continue;
    }

    if (normalized.includes(target.brand)) {
      return {
        detected: true,
        reason: `Possible impersonation of ${target.brand}. Real domain should be ${target.real}.`
      };
    }
  }

  return {
    detected: false,
    reason: ""
  };
}

module.exports = {
  scanUrl
};
