// Scam Link Detector - content.js

const SCAM_KEYWORDS = [
  "free-robux",
  "free-vbucks",
  "gift-card-generator",
  "claim-reward",
  "crypto-scam",
  "verify-account",
  "account-suspended",
  "login-verification",
  "urgent-prize",
  "free-money"
];

const SUSPICIOUS_BUTTON_TEXT = [
  "download now",
  "claim reward",
  "verify account",
  "free prize",
  "get rich",
  "install now",
  "unlock access"
];

scanPage();
observePageChanges();

function scanPage() {
  scanLinks();
  scanButtons();
  scanForms();
  scanPopups();
}

function scanLinks() {
  const links = document.querySelectorAll("a");

  links.forEach((link) => {
    const href = link.href;

    if (!href) return;

    const result = analyzeUrl(href);

    if (result.score >= 35) {
      highlightDangerousLink(link, result);
    }
  });
}

function scanButtons() {
  const buttons = document.querySelectorAll("button, a, div");

  buttons.forEach((button) => {
    const text = button.innerText?.toLowerCase();

    if (!text) return;

    for (const keyword of SUSPICIOUS_BUTTON_TEXT) {
      if (text.includes(keyword)) {
        button.style.border = "2px solid red";
        button.style.boxShadow = "0 0 10px red";
        button.setAttribute(
          "title",
          "Warning: Suspicious button detected"
        );
      }
    }
  });
}

function scanForms() {
  const passwordInputs = document.querySelectorAll(
    'input[type="password"]'
  );

  if (passwordInputs.length > 0) {
    const domain = window.location.hostname;

    if (
      domain.includes("free") ||
      domain.includes("gift") ||
      domain.includes("verify")
    ) {
      showSecurityBanner(
        "Potential phishing login page detected"
      );
    }
  }
}

function scanPopups() {
  const popupKeywords = [
    "allow notifications",
    "click allow",
    "you have won",
    "virus detected",
    "claim now"
  ];

  const allElements = document.querySelectorAll("*");

  allElements.forEach((element) => {
    const text = element.innerText?.toLowerCase();

    if (!text) return;

    for (const keyword of popupKeywords) {
      if (text.includes(keyword)) {
        element.style.border = "2px solid orange";
      }
    }
  });
}

function analyzeUrl(url) {
  let score = 0;
  const reasons = [];

  const lowerUrl = url.toLowerCase();

  for (const keyword of SCAM_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      score += 20;
      reasons.push(`Suspicious keyword: ${keyword}`);
    }
  }

  if (lowerUrl.startsWith("http://")) {
    score += 15;
    reasons.push("Website is not using HTTPS");
  }

  if (lowerUrl.includes("@")) {
    score += 20;
    reasons.push("URL contains hidden redirect character (@)");
  }

  if (lowerUrl.length > 120) {
    score += 10;
    reasons.push("Very long URL detected");
  }

  if (hasTooManyHyphens(lowerUrl)) {
    score += 10;
    reasons.push("Too many hyphens detected");
  }

  if (isIPAddress(lowerUrl)) {
    score += 25;
    reasons.push("IP address used instead of domain");
  }

  return {
    score,
    reasons
  };
}

function highlightDangerousLink(link, result) {
  link.style.backgroundColor = "rgba(255, 0, 0, 0.2)";
  link.style.border = "1px solid red";
  link.style.padding = "2px";

  link.setAttribute(
    "title",
    `Risk Score: ${result.score}\n${result.reasons.join("\n")}`
  );

  link.addEventListener("click", (event) => {
    if (result.score >= 70) {
      const proceed = confirm(
        `Warning!\n\nThis link may be dangerous.\n\nRisk Score: ${result.score}\n\nDo you still want to continue?`
      );

      if (!proceed) {
        event.preventDefault();
      }
    }
  });
}

function showSecurityBanner(message) {
  if (document.getElementById("scam-detector-banner")) return;

  const banner = document.createElement("div");

  banner.id = "scam-detector-banner";

  banner.innerText = `⚠ ${message}`;

  banner.style.position = "fixed";
  banner.style.top = "0";
  banner.style.left = "0";
  banner.style.width = "100%";
  banner.style.backgroundColor = "#b30000";
  banner.style.color = "white";
  banner.style.padding = "12px";
  banner.style.fontSize = "16px";
  banner.style.fontWeight = "bold";
  banner.style.textAlign = "center";
  banner.style.zIndex = "999999";

  document.body.appendChild(banner);
}

function hasTooManyHyphens(url) {
  const count = (url.match(/-/g) || []).length;
  return count >= 5;
}

function isIPAddress(url) {
  return /https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(url);
}

function observePageChanges() {
  const observer = new MutationObserver(() => {
    scanPage();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}
