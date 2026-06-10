const API_BASE_URL = "http://localhost:3001";

let allReports = [];

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("refreshReports").addEventListener("click", loadReports);
  document.getElementById("clearReports").addEventListener("click", clearReports);
  document.getElementById("exportCsv").addEventListener("click", exportCsv);
  document.getElementById("searchInput").addEventListener("input", applyFilters);
  document.getElementById("statusFilter").addEventListener("change", applyFilters);
  document.getElementById("categoryFilter").addEventListener("change", applyFilters);

  loadReports();
});

async function loadReports() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/reports`);
    const data = await response.json();

    allReports = data.reports || [];

    updateCategoryFilter(allReports);
    updateStats(allReports);
    renderReports(allReports);
    renderTopDomains(allReports);
  } catch (error) {
    console.error(error);
    alert("Could not load reports. Make sure backend is running.");
  }
}

function applyFilters() {
  const search = document.getElementById("searchInput").value.toLowerCase();
  const status = document.getElementById("statusFilter").value;
  const category = document.getElementById("categoryFilter").value;

  const filtered = allReports.filter((report) => {
    const text = `
      ${report.url || ""}
      ${report.reason || ""}
      ${report.category || ""}
      ${report.status || ""}
    `.toLowerCase();

    const matchesSearch = text.includes(search);
    const matchesStatus = status === "All" || report.status === status;
    const matchesCategory = category === "All" || report.category === category;

    return matchesSearch && matchesStatus && matchesCategory;
  });

  updateStats(filtered);
  renderReports(filtered);
  renderTopDomains(filtered);
}

function updateStats(reports) {
  document.getElementById("totalReports").textContent = reports.length;
  document.getElementById("safeCount").textContent =
    reports.filter((r) => r.status === "Safe").length;
  document.getElementById("suspiciousCount").textContent =
    reports.filter((r) => r.status === "Suspicious").length;
  document.getElementById("dangerousCount").textContent =
    reports.filter((r) => r.status === "Dangerous").length;

  const top = getTopDomains(reports)[0];
  document.getElementById("topDomain").textContent = top ? top.domain : "None";
}

function renderReports(reports) {
  const table = document.getElementById("reportTable");
  table.innerHTML = "";

  if (reports.length === 0) {
    table.innerHTML = `<tr><td colspan="7">No reports found.</td></tr>`;
    return;
  }

  reports.forEach((report) => {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${escapeHtml(report.url || "Unknown")}</td>
      <td>${escapeHtml(getDomain(report.url))}</td>
      <td>${escapeHtml(report.category || "Unknown")}</td>
      <td>${report.riskScore ?? 0}/100</td>
      <td class="${getStatusClass(report.status)}">${escapeHtml(report.status || "Unknown")}</td>
      <td>${escapeHtml(report.reason || "No reason")}</td>
      <td><span class="small">${formatDate(report.reportedAt)}</span></td>
    `;

    table.appendChild(row);
  });
}

function updateCategoryFilter(reports) {
  const filter = document.getElementById("categoryFilter");
  const currentValue = filter.value;

  const categories = [...new Set(
    reports.map((r) => r.category).filter(Boolean)
  )];

  filter.innerHTML = `<option value="All">All Categories</option>`;

  categories.forEach((category) => {
    const option = document.createElement("option");
    option.value = category;
    option.textContent = category;
    filter.appendChild(option);
  });

  filter.value = currentValue || "All";
}

function renderTopDomains(reports) {
  const list = document.getElementById("domainList");
  list.innerHTML = "";

  const domains = getTopDomains(reports);

  if (domains.length === 0) {
    list.innerHTML = `<li>No reported domains yet.</li>`;
    return;
  }

  domains.slice(0, 10).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = `${item.domain} — ${item.count} report(s)`;
    list.appendChild(li);
  });
}

function getTopDomains(reports) {
  const map = {};

  reports.forEach((report) => {
    const domain = getDomain(report.url);
    if (!domain) return;
    map[domain] = (map[domain] || 0) + 1;
  });

  return Object.entries(map)
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count);
}

async function clearReports() {
  const confirmClear = confirm("Delete all reports?");

  if (!confirmClear) return;

  try {
    await fetch(`${API_BASE_URL}/api/reports`, {
      method: "DELETE"
    });

    allReports = [];
    updateStats([]);
    renderReports([]);
    renderTopDomains([]);
  } catch (error) {
    console.error(error);
    alert("Could not clear reports.");
  }
}

function exportCsv() {
  if (allReports.length === 0) {
    alert("No reports to export.");
    return;
  }

  const rows = [
    ["URL", "Domain", "Category", "Risk Score", "Status", "Reason", "Reported At"],
    ...allReports.map((r) => [
      r.url || "",
      getDomain(r.url),
      r.category || "",
      r.riskScore ?? "",
      r.status || "",
      r.reason || "",
      r.reportedAt || ""
    ])
  ];

  const csv = rows
    .map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(","))
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "scam-link-reports.csv";
  a.click();

  URL.revokeObjectURL(url);
}

function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "Unknown";
  }
}

function getStatusClass(status) {
  if (status === "Dangerous") return "dangerous";
  if (status === "Suspicious") return "suspicious";
  if (status === "Safe") return "safe";
  return "";
}

function formatDate(value) {
  if (!value) return "Unknown";

  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
