const API_BASE_URL = "http://localhost:3001";

document.addEventListener("DOMContentLoaded", () => {
  loadReports();

  const refreshButton = document.getElementById("refreshReports");
  const clearButton = document.getElementById("clearReports");

  if (refreshButton) {
    refreshButton.addEventListener("click", loadReports);
  }

  if (clearButton) {
    clearButton.addEventListener("click", clearReports);
  }
});

async function loadReports() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/reports`);
    const data = await response.json();

    const reports = data.reports || [];

    updateStats(reports);
    renderReports(reports);
  } catch (error) {
    console.error("Failed to load reports:", error);
    alert("Could not load reports. Make sure the backend is running.");
  }
}

function updateStats(reports) {
  const totalReports = reports.length;
  const safeCount = reports.filter((r) => r.status === "Safe").length;
  const suspiciousCount = reports.filter((r) => r.status === "Suspicious").length;
  const dangerousCount = reports.filter((r) => r.status === "Dangerous").length;

  document.getElementById("totalReports").textContent = totalReports;
  document.getElementById("safeCount").textContent = safeCount;
  document.getElementById("suspiciousCount").textContent = suspiciousCount;
  document.getElementById("dangerousCount").textContent = dangerousCount;
}

function renderReports(reports) {
  const table = document.getElementById("reportTable");
  table.innerHTML = "";

  if (reports.length === 0) {
    table.innerHTML = `
      <tr>
        <td colspan="5">No reports yet.</td>
      </tr>
    `;
    return;
  }

  reports.forEach((report) => {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${escapeHtml(report.url || "Unknown URL")}</td>
      <td>${escapeHtml(report.category || "Unknown")}</td>
      <td>${report.riskScore ?? 0}</td>
      <td class="${getStatusClass(report.status)}">${escapeHtml(report.status || "Unknown")}</td>
      <td>${escapeHtml(report.reason || "No reason provided")}</td>
    `;

    table.appendChild(row);
  });
}

async function clearReports() {
  const confirmClear = confirm("Are you sure you want to delete all reports?");

  if (!confirmClear) return;

  try {
    await fetch(`${API_BASE_URL}/api/reports`, {
      method: "DELETE"
    });

    loadReports();
  } catch (error) {
    console.error("Failed to clear reports:", error);
    alert("Could not clear reports.");
  }
}

function getStatusClass(status) {
  if (status === "Dangerous") return "dangerous";
  if (status === "Suspicious") return "suspicious";
  if (status === "Safe") return "safe";
  return "";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
