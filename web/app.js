"use strict";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

let currentReport = null;

const riskLevelEl = document.getElementById("risk-level");
const totalAlertsEl = document.getElementById("total-alerts");
const filesAnalyzedEl = document.getElementById("files-analyzed");
const totalLinesEl = document.getElementById("total-lines");
const severityListEl = document.getElementById("severity-list");
const ipListEl = document.getElementById("ip-list");
const alertsEl = document.getElementById("alerts");
const severityFilterEl = document.getElementById("severity-filter");
const reportInputEl = document.getElementById("report-input");

function text(value) {
  return value === undefined || value === null ? "" : String(value);
}

function summarize(report) {
  const summary = report.summary || {};
  const alerts = Array.isArray(report.alerts) ? report.alerts : [];
  const severityCounts = summary.severity_counts || {};
  const categoryCounts = summary.category_counts || {};
  const topIps = summary.top_offending_ips || [];

  if (!summary.risk_level) {
    for (const severity of SEVERITIES) {
      severityCounts[severity] = alerts.filter((alert) => alert.severity === severity).length;
    }
  }

  return {
    riskLevel: summary.risk_level || (alerts.length ? "REVIEW" : "LOW"),
    severityCounts,
    categoryCounts,
    topIps,
    alerts,
  };
}

function renderMetricList(target, rows, emptyText) {
  target.textContent = "";
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "metric-label";
    empty.textContent = emptyText;
    target.appendChild(empty);
    return;
  }

  for (const [label, value] of rows) {
    const row = document.createElement("div");
    row.className = "metric-row";
    const labelEl = document.createElement("span");
    labelEl.className = "metric-label";
    labelEl.textContent = label;
    const valueEl = document.createElement("span");
    valueEl.className = "metric-value";
    valueEl.textContent = text(value);
    row.append(labelEl, valueEl);
    target.appendChild(row);
  }
}

function renderAlerts(alerts) {
  alertsEl.textContent = "";
  const selected = severityFilterEl.value;
  const filtered = selected === "ALL"
    ? alerts
    : alerts.filter((alert) => alert.severity === selected);

  if (!filtered.length) {
    const empty = document.createElement("p");
    empty.className = "metric-label";
    empty.textContent = "No alerts match this filter.";
    alertsEl.appendChild(empty);
    return;
  }

  for (const alert of filtered) {
    const card = document.createElement("article");
    card.className = `alert ${alert.severity || "LOW"}`;

    const title = document.createElement("div");
    title.className = "alert-title";

    const heading = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = `${text(alert.rule_name)} (${text(alert.rule_id)})`;
    const meta = document.createElement("div");
    meta.className = "alert-meta";
    meta.textContent = `${text(alert.category)} | ${text(alert.mitre)} | ${text(alert.file)}:${text(alert.line_number)}`;
    heading.append(name, meta);

    const badge = document.createElement("span");
    badge.className = `badge ${alert.severity || "LOW"}`;
    badge.textContent = text(alert.severity || "LOW");

    title.append(heading, badge);

    const description = document.createElement("p");
    description.textContent = text(alert.description);

    const snippet = document.createElement("pre");
    snippet.className = "snippet";
    snippet.textContent = text(alert.line_content);

    card.append(title, description, snippet);
    alertsEl.appendChild(card);
  }
}

function render(report) {
  currentReport = report;
  const summary = summarize(report);

  riskLevelEl.textContent = summary.riskLevel;
  riskLevelEl.className = summary.riskLevel;
  totalAlertsEl.textContent = text(report.total_alerts ?? summary.alerts.length);
  filesAnalyzedEl.textContent = text(Array.isArray(report.files_analyzed) ? report.files_analyzed.length : 0);
  totalLinesEl.textContent = Number(report.total_lines || 0).toLocaleString();

  renderMetricList(
    severityListEl,
    SEVERITIES.map((severity) => [severity, summary.severityCounts[severity] || 0]),
    "No severity data."
  );

  renderMetricList(
    ipListEl,
    summary.topIps.map((item) => [item.ip, item.alert_count]),
    "No IP addresses found in alert snippets."
  );

  renderAlerts(summary.alerts);
}

reportInputEl.addEventListener("change", async (event) => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  const content = await file.text();
  render(JSON.parse(content));
});

severityFilterEl.addEventListener("change", () => {
  if (currentReport) renderAlerts(summarize(currentReport).alerts);
});

fetch("./sample-report.json")
  .then((response) => response.json())
  .then(render)
  .catch(() => {
    alertsEl.textContent = "Could not load sample-report.json.";
  });
