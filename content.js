let scanTimeout;

const DANGEROUS_FILE_TYPES = [
  ".exe", ".scr", ".bat", ".cmd", ".msi", ".apk",
  ".jar", ".vbs", ".ps1", ".reg", ".dll", ".iso"
];

const SUSPICIOUS_BUTTON_TEXT = [
  "download now",
  "claim reward",
  "verify account",
  "free prize",
  "click allow",
  "allow notifications",
  "install now",
  "unlock access",
  "you have won",
  "claim now",
  "limited time",
  "act now",
  "free robux",
  "free vbucks"
];

const SUSPICIOUS_PAGE_TEXT = [
  "your device is infected",
  "virus detected",
  "click allow to continue",
  "enable notifications to verify",
  "you have won",
  "claim your reward",
  "account suspended",
  "verify your wallet",
  "enter your seed phrase",
  "free gift card",
  "dark web",
  "darknet",
  ".onion",
  "keylogger",
  "token grabber",
  "cookie logger",
  "phishing kit",
  "malware builder"
];

initProtection();

function initProtection() {
  chrome.storage.local.get(["protectionEnabled"], (settings) => {
    if (settings.protectionEnabled === false) return;

    scanPage();
    protectClicks();
    observePageChanges();
  });
}

function scanPage() {
  scanLinks();
  scanButtons();
  scanForms();
  scanPageText();
}

function scanLinks() {
  const links = document.querySelectorAll("a[href]");

  links.forEach((link) => {
    if (link.dataset.scamChecked === "true") return;

    link.dataset.scamChecked = "true";

    chrome.runtime.sendMessage(
      {
        type: "SCAN_URL",
        url: link.href
      },
      (result) => {
        if (!result) return;

        if (result.score >= 35) {
          markRiskyElement(link, result);
        }
      }
    );
  });
}

function scanButtons() {
  const elements = document.querySelectorAll("button, a, div, span");

  elements.forEach((element) => {
    const text = (element.innerText || "").toLowerCase().trim();

    if (!text) return;

    for (const keyword of SUSPICIOUS_BUTTON_TEXT) {
      if (text.includes(keyword)) {
        markSuspiciousTextElement(
          element,
          `Suspicious button/ad text detected: ${keyword}`
        );
      }
    }
  });
}

function scanForms() {
  const passwordInputs = document.querySelectorAll('input[type="password"]');

  if (passwordInputs.length === 0) return;

  const pageText = document.body.innerText.toLowerCase();
  const url = window.location.href.toLowerCase();

  const riskyLogin =
    pageText.includes("verify") ||
    pageText.includes("suspended") ||
    pageText.includes("wallet") ||
    pageText.includes("seed phrase") ||
    url.includes("verify") ||
    url.includes("login") ||
    url.includes("account");

  if (riskyLogin) {
    showSecurityBanner(
      "Potential phishing login or credential theft page detected."
    );
  }
}

function scanPageText() {
  const text = document.body.innerText.toLowerCase();

  const matches = [];

  for (const keyword of SUSPICIOUS_PAGE_TEXT) {
    if (text.includes(keyword)) {
      matches.push(keyword);
    }
  }

  if (matches.length >= 2) {
    showSecurityBanner(
      `Suspicious page content detected: ${matches.slice(0, 3).join(", ")}`
    );
  }
}

function protectClicks() {
  document.addEventListener(
    "click",
    (event) => {
      const link = event.target.closest("a[href]");

      if (!link) return;

      const href = link.href.toLowerCase();

      for (const fileType of DANGEROUS_FILE_TYPES) {
        if (href.includes(fileType)) {
          const proceed = confirm(
            `Warning!\n\nThis link may download a dangerous file type: ${fileType}\n\nOnly continue if you fully trust this website.`
          );

          if (!proceed) {
            event.preventDefault();
            event.stopPropagation();
          }

          return;
        }
      }

      chrome.runtime.sendMessage(
        {
          type: "SCAN_URL",
          url: link.href
        },
        (result) => {
          if (!result) return;

          if (result.score >= 70) {
            const proceed = confirm(
              `Dangerous link detected!\n\nStatus: ${result.status}\nRisk Score: ${result.score}/100\nCategory: ${result.category}\n\nReasons:\n${result.reasons.join(
                "\n"
              )}\n\nDo you still want to continue?`
            );

            if (!proceed) {
              event.preventDefault();
              event.stopPropagation();
            }
          }
        }
      );
    },
    true
  );
}

function markRiskyElement(element, result) {
  element.style.backgroundColor = "rgba(255, 106, 0, 0.16)";
  element.style.outline = "2px solid #ff6a00";
  element.style.borderRadius = "5px";

  element.setAttribute(
    "title",
    `Scam Link Detector\nStatus: ${result.status}\nScore: ${result.score}/100\nCategory: ${result.category}\n${result.reasons.join("\n")}`
  );

  addBadge(element, result);
}

function markSuspiciousTextElement(element, reason) {
  if (element.dataset.scamTextChecked === "true") return;

  element.dataset.scamTextChecked = "true";
  element.style.outline = "2px solid #ff6a00";
  element.style.borderRadius = "5px";

  element.setAttribute(
    "title",
    `Scam Link Detector Warning\n${reason}`
  );
}

function addBadge(element, result) {
  if (element.dataset.scamBadgeAdded === "true") return;

  element.dataset.scamBadgeAdded = "true";

  const badge = document.createElement("span");

  badge.textContent = ` ⚠ ${result.status} (${result.score})`;
  badge.style.marginLeft = "6px";
  badge.style.padding = "2px 6px";
  badge.style.borderRadius = "6px";
  badge.style.fontSize = "12px";
  badge.style.fontWeight = "bold";
  badge.style.background = result.score >= 70 ? "#ff2f00" : "#ff6a00";
  badge.style.color = "#ffffff";
  badge.style.zIndex = "999999";

  element.appendChild(badge);
}

function showSecurityBanner(message) {
  if (document.getElementById("scam-detector-banner")) return;

  const banner = document.createElement("div");
  banner.id = "scam-detector-banner";

  banner.innerHTML = `
    <strong>⚠ Scam Link Detector:</strong> ${message}
    <button id="scam-detector-close">Dismiss</button>
  `;

  banner.style.position = "fixed";
  banner.style.top = "0";
  banner.style.left = "0";
  banner.style.width = "100%";
  banner.style.background = "#ff6a00";
  banner.style.color = "#ffffff";
  banner.style.padding = "12px";
  banner.style.fontSize = "15px";
  banner.style.fontWeight = "bold";
  banner.style.textAlign = "center";
  banner.style.zIndex = "999999999";
  banner.style.boxShadow = "0 4px 12px rgba(0,0,0,0.25)";

  document.documentElement.appendChild(banner);

  const closeButton = document.getElementById("scam-detector-close");

  closeButton.style.marginLeft = "12px";
  closeButton.style.padding = "6px 10px";
  closeButton.style.border = "none";
  closeButton.style.borderRadius = "6px";
  closeButton.style.cursor = "pointer";
  closeButton.style.background = "#ffffff";
  closeButton.style.color = "#111111";
  closeButton.style.fontWeight = "bold";

  closeButton.addEventListener("click", () => {
    banner.remove();
  });
}

function observePageChanges() {
  const observer = new MutationObserver(() => {
    clearTimeout(scanTimeout);

    scanTimeout = setTimeout(() => {
      scanPage();
    }, 800);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
}
