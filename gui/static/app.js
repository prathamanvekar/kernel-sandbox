const policySelect = document.getElementById("policySelect");
const targetInput = document.getElementById("targetInput");
const argsInput = document.getElementById("argsInput");
const workloadLabelInput = document.getElementById("workloadLabelInput");
const benchIterationsInput = document.getElementById("benchIterationsInput");
const stdoutEl = document.getElementById("stdout");
const stderrEl = document.getElementById("stderr");
const logTailEl = document.getElementById("logTail");
const reportContentEl = document.getElementById("reportContent");
const reportsListEl = document.getElementById("reportsList");
const policyPreviewEl = document.getElementById("policyPreview");
const exitCodeChip = document.getElementById("exitCodeChip");
const cmdChip = document.getElementById("cmdChip");
const statusLine = document.getElementById("statusLine");
const featureListEl = document.getElementById("featureList");

function humanFeatureName(key) {
  return key.replace(/_/g, " ");
}

function displayReportName(fileName) {
  return fileName
    .replace(/^report_/, "")
    .replace(/\.md$/, "")
    .replace(/_/g, " ");
}

function setStatus(msg, kind = "info") {
  statusLine.textContent = msg;
  statusLine.style.color = kind === "error" ? "var(--danger)" : "var(--muted)";
}

function setOutput(result) {
  stdoutEl.textContent = result.stdout || "";
  stderrEl.textContent = result.stderr || "";
  exitCodeChip.textContent = `exit: ${result.exit_code}`;
  cmdChip.textContent = `command: ${result.command || "n/a"}`;
  setStatus(
    result.exit_code === 0
      ? "Command completed successfully."
      : "Command finished with non-zero exit code.",
    result.exit_code === 0 ? "info" : "error",
  );
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Request failed: ${res.status}`);
  }
  return res.json();
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    throw new Error(`Request failed: ${res.status}`);
  }
  return res.json();
}

async function refreshState() {
  try {
    const state = await getJson("/api/state");

    const current = policySelect.value;
    policySelect.innerHTML = "";
    for (const p of state.policies) {
      const opt = document.createElement("option");
      opt.value = `policies/${p}`;
      opt.textContent = p;
      policySelect.appendChild(opt);
    }
    if (
      current &&
      Array.from(policySelect.options).some((o) => o.value === current)
    ) {
      policySelect.value = current;
    }

    logTailEl.textContent = state.log_tail || "(no sandbox.log yet)";

    featureListEl.innerHTML = "";
    for (const [key, enabled] of Object.entries(state.features || {})) {
      const li = document.createElement("li");
      li.className = enabled ? "ok" : "";
      li.textContent = `${enabled ? "[OK]" : "[--]"} ${humanFeatureName(key)}`;
      featureListEl.appendChild(li);
    }

    reportsListEl.innerHTML = "";
    for (const [idx, rep] of state.reports.entries()) {
      const li = document.createElement("li");
      if (idx === 0) {
        li.classList.add("latest");
      }
      const btn = document.createElement("button");
      btn.title = rep;
      if (idx === 0) {
        btn.innerHTML = `<span class="report-tag">LATEST</span>${displayReportName(rep)}`;
      } else {
        btn.textContent = displayReportName(rep);
      }
      btn.addEventListener("click", () => loadReport(rep));
      li.appendChild(btn);
      reportsListEl.appendChild(li);
    }

    await loadPolicyPreview();
    if (!reportContentEl.textContent && state.reports.length > 0) {
      await loadReport(state.reports[0]);
    }

    setStatus("State refreshed.");
  } catch (err) {
    setStatus(`Failed to refresh state: ${err.message}`, "error");
  }
}

async function loadPolicyPreview() {
  const selected = policySelect.value;
  if (!selected) {
    policyPreviewEl.textContent = "";
    return;
  }
  const name = selected.replace(/^policies\//, "");
  const payload = await getJson(`/api/policy?name=${encodeURIComponent(name)}`);
  policyPreviewEl.textContent = payload.content || "(empty policy)";
}

async function loadReport(name) {
  try {
    const payload = await getJson(
      `/api/report?name=${encodeURIComponent(name)}`,
    );
    reportContentEl.textContent = payload.content || "(empty report)";
  } catch (err) {
    setStatus(`Failed to load report: ${err.message}`, "error");
  }
}

async function runAction(url) {
  try {
    setStatus("Running command...");
    const result = await postJson(url, {
      policy: policySelect.value || "policies/restrictive.json",
      target: targetInput.value || "./test",
      args: argsInput.value || "",
      workloadLabel: workloadLabelInput.value || "ad-hoc",
      iterations: benchIterationsInput.value || "5",
    });
    setOutput(result);
    await refreshState();
  } catch (err) {
    setStatus(`Action failed: ${err.message}`, "error");
  }
}

document
  .getElementById("buildBtn")
  .addEventListener("click", () => runAction("/api/build"));
document
  .getElementById("runBtn")
  .addEventListener("click", () => runAction("/api/run"));
document
  .getElementById("sandboxBtn")
  .addEventListener("click", () => runAction("/api/sandbox"));
document
  .getElementById("reportBtn")
  .addEventListener("click", () => runAction("/api/make-report"));
document
  .getElementById("suiteBtn")
  .addEventListener("click", () => runAction("/api/demo-suite"));
document
  .getElementById("benchmarkBtn")
  .addEventListener("click", () => runAction("/api/benchmark"));
document
  .getElementById("refreshBtn")
  .addEventListener("click", () => refreshState());
policySelect.addEventListener("change", () => loadPolicyPreview());

refreshState();
