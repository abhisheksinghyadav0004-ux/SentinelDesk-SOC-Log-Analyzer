const uploadForm = document.querySelector("#uploadForm");
const logFileInput = document.querySelector("#logFile");
const fileLabel = document.querySelector("#fileLabel");
const fileDropZone = document.querySelector(".file-drop-zone");
const analyzeButton = document.querySelector("#analyzeButton");

const eventsProcessed = document.querySelector("#eventsProcessed");
const failedLogins = document.querySelector("#failedLogins");
const alertsGenerated = document.querySelector("#alertsGenerated");
const riskScore = document.querySelector("#riskScore");
const riskCaption = document.querySelector("#riskCaption");


const alertCount = document.querySelector("#alertCount");
const alertList = document.querySelector("#alertList");

const riskBarFill = document.querySelector("#riskBarFill");
const riskExplanation = document.querySelector("#riskExplanation");
const timelineList = document.querySelector("#timelineList");
const timelineCount = document.querySelector("#timelineCount");

const downloadReportButton = document.querySelector("#downloadReportButton");
const analystNotes = document.querySelector("#analystNotes");
const saveNotesButton = document.querySelector("#saveNotesButton");
const notesStatus = document.querySelector("#notesStatus");

const filterButtons = document.querySelectorAll(".filter-button");

let currentAlerts = [];
let activeSeverity = "All";

let latestAnalysis = null;
let savedAlertStatuses = JSON.parse(
  localStorage.getItem("sentineldeskAlertStatuses") || "{}"
);


function getAlertKey(alert) {
  return alert.title + "|" + alert.evidence;
}


function getAlertStatus(alert) {
  const alertKey = getAlertKey(alert);

  return savedAlertStatuses[alertKey] || alert.status;
}


function updateAlertStatus(alert, newStatus) {
  const alertKey = getAlertKey(alert);

  savedAlertStatuses[alertKey] = newStatus;
  alert.status = newStatus;

  localStorage.setItem(
    "sentineldeskAlertStatuses",
    JSON.stringify(savedAlertStatuses)
  );

  applyAlertFilter();
}
analystNotes.value =
  localStorage.getItem("sentineldeskAnalystNotes") || "";


logFileInput.addEventListener("change", function () {
  const selectedFile = logFileInput.files[0];

  fileLabel.textContent = selectedFile
    ? selectedFile.name
    : "Choose a security log file";
});

["dragenter", "dragover"].forEach(function (eventName) {
  fileDropZone.addEventListener(eventName, function (event) {
    event.preventDefault();
    fileDropZone.classList.add("drag-active");
  });
});


["dragleave", "drop"].forEach(function (eventName) {
  fileDropZone.addEventListener(eventName, function (event) {
    event.preventDefault();
    fileDropZone.classList.remove("drag-active");
  });
});


fileDropZone.addEventListener("drop", function (event) {
  const droppedFile = event.dataTransfer.files[0];

  if (!droppedFile) {
    return;
  }

  if (!droppedFile.name.match(/\.(log|txt|csv)$/i)) {
  showError("Only .log, .txt, and .csv files are supported.");
  return;
}

  const transfer = new DataTransfer();

  transfer.items.add(droppedFile);
  logFileInput.files = transfer.files;

  fileLabel.textContent = droppedFile.name;
});


uploadForm.addEventListener("submit", async function (event) {
  event.preventDefault();

  const selectedFile = logFileInput.files[0];

  if (!selectedFile) {
    showError("Please select a .log or .txt file first.");
    return;
  }

  const formData = new FormData();
  formData.append("logFile", selectedFile);

  analyzeButton.disabled = true;
  analyzeButton.textContent = "Analyzing...";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      body: formData
    });

    const responseText = await response.text();

let data;

try {
  data = JSON.parse(responseText);
} catch (error) {
  throw new Error(
    "Server returned an invalid response. Check the Flask terminal for errors."
  );
}

    if (!response.ok) {
      throw new Error(data.error || "Log analysis failed.");
    }

    renderAnalysis(data);
  } catch (error) {
    showError(error.message);
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = "Run Analysis";
  }
});


function renderAnalysis(data) {
  latestAnalysis = data;
  downloadReportButton.disabled = false;

  const summary = data.summary;

  eventsProcessed.textContent = summary.eventsProcessed;
  failedLogins.textContent = summary.failedLogins;
  alertsGenerated.textContent = summary.alertsGenerated;
  riskScore.textContent = summary.riskScore + "/100";

  
  alertCount.textContent = summary.alertsGenerated + " Alerts";

  riskBarFill.style.width = summary.riskScore + "%";

  if (summary.riskScore >= 70) {
    riskCaption.textContent = "High investigation priority";

    riskExplanation.textContent =
      "Critical risk detected. Immediate SOC investigation is recommended.";
  } else if (summary.riskScore >= 35) {
    riskCaption.textContent = "Needs analyst review";

    riskExplanation.textContent =
      "Moderate risk detected. Review the alert queue and validate evidence.";
  } else {
    riskCaption.textContent = "Low observed risk";

    riskExplanation.textContent =
      "No major malicious pattern was detected in the uploaded log.";
  }

    currentAlerts = data.alerts;
applyAlertFilter();
  renderTimeline(data.timeline || []);
}

function applyAlertFilter() {
  const filteredAlerts = currentAlerts.filter(function (alert) {
    return activeSeverity === "All" || alert.severity === activeSeverity;
  });

  alertCount.textContent =
    filteredAlerts.length + " / " + currentAlerts.length + " Alerts";

  renderAlerts(filteredAlerts);
}

function renderAlerts(alerts) {
  alertList.replaceChildren();

  if (alerts.length === 0) {
    const message = document.createElement("p");

    message.className = "empty-message";
    message.textContent =
      "No security rule matches found. Continue monitoring this system.";

    alertList.appendChild(message);
    return;
  }

  alerts.forEach(function (alert) {
    const currentStatus = getAlertStatus(alert);

    const alertCard = document.createElement("article");

    alertCard.className =
      "alert-item " + alert.severity.toLowerCase();

    const meta = document.createElement("div");
    meta.className = "alert-meta";

    const badge = document.createElement("span");
    badge.className = "alert-badge";
    badge.textContent = alert.severity;

    const status = document.createElement("span");
    status.className = "alert-status";
    status.textContent = currentStatus;

    meta.appendChild(badge);
    meta.appendChild(status);

    const title = document.createElement("h3");
    title.textContent = alert.title;

    const evidence = document.createElement("p");
    evidence.className = "alert-evidence";
    evidence.textContent = "Evidence: " + alert.evidence;

    const action = document.createElement("p");
    action.className = "alert-action";
    action.textContent =
      "Recommended action: " + alert.recommendation;

    const footer = document.createElement("div");
    footer.className = "alert-footer";

    const source = document.createElement("span");
    source.textContent = "SOC Detection Rule";

    const actionButtons = document.createElement("div");
    actionButtons.className = "alert-actions";

    const investigateButton = document.createElement("button");
    investigateButton.className = "investigate-button";
    investigateButton.type = "button";
    investigateButton.textContent = "Investigating";

    investigateButton.addEventListener("click", function () {
      updateAlertStatus(alert, "Investigating");
    });

    const resolveButton = document.createElement("button");
    resolveButton.className = "resolve-button";
    resolveButton.type = "button";
    resolveButton.textContent = "Resolve";

    resolveButton.addEventListener("click", function () {
      updateAlertStatus(alert, "Resolved");
    });

    if (currentStatus === "Resolved") {
      investigateButton.disabled = true;
      resolveButton.disabled = true;
      resolveButton.textContent = "Resolved";
    }

    actionButtons.appendChild(investigateButton);
    actionButtons.appendChild(resolveButton);

    footer.appendChild(source);
    footer.appendChild(actionButtons);

    alertCard.appendChild(meta);
    alertCard.appendChild(title);
    alertCard.appendChild(evidence);
    alertCard.appendChild(action);
    alertCard.appendChild(footer);

    alertList.appendChild(alertCard);
  });
}

function renderTimeline(timeline) {
  timelineList.replaceChildren();

  timelineCount.textContent = timeline.length + " Events";

  if (timeline.length === 0) {
    const message = document.createElement("p");

    message.className = "empty-message";
    message.textContent = "No timeline events were found.";

    timelineList.appendChild(message);
    return;
  }

  timeline.forEach(function (item) {
    const row = document.createElement("div");

    row.className = "timeline-row";

    const time = document.createElement("span");
    time.textContent = item.time;

    const event = document.createElement("span");
    event.textContent = item.event;

    const user = document.createElement("span");
    user.textContent = item.user;

    const ip = document.createElement("span");
    ip.textContent = item.ip;

    row.appendChild(time);
    row.appendChild(event);
    row.appendChild(user);
    row.appendChild(ip);

    timelineList.appendChild(row);
  });
}


function showError(message) {
  alertList.replaceChildren();

  const errorMessage = document.createElement("p");

  errorMessage.className = "empty-message";
  errorMessage.textContent = "Error: " + message;

  alertList.appendChild(errorMessage);
}


downloadReportButton.addEventListener("click", function () {
  if (!latestAnalysis) {
    return;
  }

  const report = {
    reportTitle: "SentinelDesk SOC Investigation Report",
    generatedAt: new Date().toLocaleString(),
    sourceFile: latestAnalysis.filename,
    summary: latestAnalysis.summary,
    alerts: latestAnalysis.alerts,
    timeline: latestAnalysis.timeline,
    analystNotes: analystNotes.value
  };

  const reportText = JSON.stringify(report, null, 2);

  const reportBlob = new Blob(
    [reportText],
    { type: "application/json" }
  );

  const downloadUrl = URL.createObjectURL(reportBlob);

  const downloadLink = document.createElement("a");

  downloadLink.href = downloadUrl;
  downloadLink.download = "sentineldesk-investigation-report.json";

  document.body.appendChild(downloadLink);
  downloadLink.click();
  downloadLink.remove();

  URL.revokeObjectURL(downloadUrl);
});
filterButtons.forEach(function (button) {
  button.addEventListener("click", function () {
    activeSeverity = button.dataset.severity;

    filterButtons.forEach(function (item) {
      item.classList.remove("active-filter");
    });

    button.classList.add("active-filter");

    applyAlertFilter();
  });
});
saveNotesButton.addEventListener("click", function () {
  localStorage.setItem(
    "sentineldeskAnalystNotes",
    analystNotes.value
  );

  notesStatus.textContent = "Notes saved locally.";

  setTimeout(function () {
    notesStatus.textContent = "";
  }, 2500);
});