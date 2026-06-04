const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const { scanUrl } = require("./threatEngine");

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
  try {
    const data = fs.readFileSync(reportsFile, "utf8");
    return JSON.parse(data || "[]");
  } catch (error) {
    console.error(error);
    return [];
  }
}

function saveReports(reports) {
  fs.writeFileSync(reportsFile, JSON.stringify(reports, null, 2));
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Scam Link Detector Backend is running",
    version: "2.0.0"
  });
});

app.post("/api/check-url", (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required"
    });
  }

  try {
    const result = scanUrl(url);

    res.json({
      success: true,
      result
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Scan failed"
    });
  }
});

app.post("/api/report", (req, res) => {
  const {
    url,
    title,
    reason,
    category
  } = req.body;

  if (!url || !reason) {
    return res.status(400).json({
      success: false,
      error: "URL and reason are required"
    });
  }

  const reports = readReports();

  const scanResult = scanUrl(url);

  const newReport = {
    id: Date.now(),
    url,
    title: title || "Unknown title",
    reason,
    category: category || scanResult.category,
    riskScore: scanResult.score,
    status: scanResult.status,
    scanReasons: scanResult.reasons,
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
    success: true,
    totalReports: reports.length,
    reports
  });
});

app.get("/api/stats", (req, res) => {
  const reports = readReports();

  const stats = {
    totalReports: reports.length,
    safeReports: reports.filter(
      (r) => r.status === "Safe"
    ).length,

    suspiciousReports: reports.filter(
      (r) => r.status === "Suspicious"
    ).length,

    dangerousReports: reports.filter(
      (r) => r.status === "Dangerous"
    ).length
  };

  res.json({
    success: true,
    stats
  });
});

app.delete("/api/reports", (req, res) => {
  saveReports([]);

  res.json({
    success: true,
    message: "All reports deleted"
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found"
  });
});

app.listen(PORT, () => {
  console.log(
    `Scam Link Detector Backend running on port ${PORT}`
  );
});
