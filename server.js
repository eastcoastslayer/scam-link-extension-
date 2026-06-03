const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

const dataDir = path.join(__dirname, "data");
const reportsFile = path.join(dataDir, "reports.json");

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

if (!fs.existsSync(reportsFile)) {
  fs.writeFileSync(reportsFile, JSON.stringify([], null, 2));
}

function readReports() {
  const data = fs.readFileSync(reportsFile, "utf8");
  return JSON.parse(data || "[]");
}

function saveReports(reports) {
  fs.writeFileSync(reportsFile, JSON.stringify(reports, null, 2));
}

function scanUrl(url) {
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

app.get("/", (req, res) => {
  res.json({
    message: "Scam Link Detector Backend is running",
    status: "online"
  });
});

app.post("/api/check-url", (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      error: "URL is required"
    });
  }

  const result = scanUrl(url);
  res.json(result);
});

app.post("/api/report", (req, res) => {
  const { url, title, reason, category } = req.body;

  if (!url || !reason) {
    return res.status(400).json({
      error: "URL and reason are required"
    });
  }

  const reports = readReports();

  const newReport = {
    id: Date.now(),
    url,
    title: title || "Unknown title",
    reason,
    category: category || "User Report",
    reportedAt: new Date().toISOString()
  };

  reports.unshift(newReport);
  saveReports(reports);

  res.status(201).json({
    success: true,
    message: "Report saved successfully",
    report: newReport
  });
});

app.get("/api/reports", (req, res) => {
  const reports = readReports();

  res.json({
    totalReports: reports.length,
    reports
  });
});

app.listen(PORT, () => {
  console.log(`Scam Link Detector Backend running on port ${PORT}`);
});
