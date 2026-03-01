const environmentInput = document.getElementById("environment");
const regionInput = document.getElementById("region");
const subRegionInput = document.getElementById("subRegion");
const subRegionChips = document.getElementById("subRegionChips");
const allSubRegionsToggle = document.getElementById("allSubRegionsToggle");
const cleanSubRegionsBtn = document.getElementById("cleanSubRegionsBtn");
const hostInput = document.getElementById("host");
const hostChips = document.getElementById("hostChips");
const allHostsToggle = document.getElementById("allHostsToggle");
const filterInput = document.getElementById("filter");
const outputDirNameInput = document.getElementById("outputDirName");
const timeoutMinutesInput = document.getElementById("timeoutMinutes");
const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const cleanBtn = document.getElementById("cleanBtn");
const captureModeBtn = document.getElementById("captureModeBtn");
const processBtn = document.getElementById("processBtn");
const mediaDirPicker = document.getElementById("mediaDirPicker");
const mediaSourcePanel = document.getElementById("mediaSourcePanel");
const chooseLocalMediaBtn = document.getElementById("chooseLocalMediaBtn");
const showS3MediaBtn = document.getElementById("showS3MediaBtn");
const mediaSourceStatus = document.getElementById("mediaSourceStatus");
const s3ImportPanel = document.getElementById("s3ImportPanel");
const s3SessionSelect = document.getElementById("s3SessionSelect");
const refreshS3SessionsBtn = document.getElementById("refreshS3SessionsBtn");
const importS3SessionBtn = document.getElementById("importS3SessionBtn");
const s3ImportStatus = document.getElementById("s3ImportStatus");
const showLogsToggle = document.getElementById("showLogsToggle");
const captureLeaveModal = document.getElementById("captureLeaveModal");
const stayOnCaptureBtn = document.getElementById("stayOnCaptureBtn");
const leaveAndCancelBtn = document.getElementById("leaveAndCancelBtn");

const statusBox = document.getElementById("status");
const criticalStatusBox = document.getElementById("criticalStatus");
const counterBox = document.getElementById("counter");
const rawFiles = document.getElementById("rawFiles");
const captureStorageHint = document.getElementById("captureStorageHint");
const postSection = document.getElementById("postSection");
const finalResults = document.getElementById("finalResults");
const correlateProgress = document.getElementById("correlateProgress");
const s3FlushNotice = document.getElementById("s3FlushNotice");
const s3FlushNoticeText = document.getElementById("s3FlushNoticeText");
const stopFlushBtn = document.getElementById("stopFlushBtn");
const resumeFlushBtn = document.getElementById("resumeFlushBtn");
const cancelCorrelationBtn = document.getElementById("cancelCorrelationBtn");
const correlateBtn = document.getElementById("correlateBtn");
const sipPcapInput = document.getElementById("sipPcap");
const callDirectionInput = document.getElementById("callDirection");
const homepageBtn = document.getElementById("homepageBtn");
const restartCaptureBtn = document.getElementById("restartCaptureBtn");
const captureLocationPanel = document.getElementById("captureLocationPanel");
const captureLocationLocal = document.getElementById("captureLocationLocal");
const captureLocationS3 = document.getElementById("captureLocationS3");
const captureLocationDisclaimer = document.getElementById("captureLocationDisclaimer");
const captureLocationContinueBtn = document.getElementById("captureLocationContinueBtn");
const captureLocationBackBtn = document.getElementById("captureLocationBackBtn");
const s3SpoolDirPanel = document.getElementById("s3SpoolDirPanel");
const chooseS3SpoolDirBtn = document.getElementById("chooseS3SpoolDirBtn");

const cleanSelectionBtn = document.getElementById("cleanSelectionBtn");

const homePanel = document.getElementById("homePanel");
const environmentPanel = document.getElementById("environmentPanel");
const captureFlowPanel = document.getElementById("captureFlowPanel");
const regionStatus = document.getElementById("regionStatus");
const subRegionStatus = document.getElementById("subRegionStatus");
const subRegionFlowPanel = document.getElementById("subRegionPanel");
const noReachablePanel = document.getElementById("noReachablePanel");
const noReachableMessage = document.getElementById("noReachableMessage");
const retryReachabilityBtn = document.getElementById("retryReachabilityBtn");
const noReachableAutoInfo = document.getElementById("noReachableAutoInfo");
const captureRecoveryPanel = document.getElementById("captureRecoveryPanel");
const captureRecoveryCountdown = document.getElementById("captureRecoveryCountdown");
const captureRecoveryProgress = document.getElementById("captureRecoveryProgress");
const hostPanel = document.getElementById("hostPanel");
const livePanel = document.getElementById("livePanel");
const logSection = document.getElementById("logSection");

const downloadLogBtn = document.getElementById("downloadLogBtn");
const clearLogBtn = document.getElementById("clearLogBtn");
const appLog = document.getElementById("appLog");

const projectLogLevel = String(document.body.dataset.projectLogLevel || "INFO").toUpperCase();
const captureRootConfigured = String(document.body.dataset.captureRoot || "");
const s3EnabledInApp = String(document.body.dataset.s3Enabled || "0") === "1";
const s3ConfiguredInApp = String(document.body.dataset.s3Configured || "0") === "1";
const DEBUG_ENABLED = projectLogLevel === "DEBUG";

let statusTimer = null;
let logPollTimer = null;
let correlationLiveLogTimer = null;
let logEventSource = null;
let correlationWaitAbortController = null;
let activeCorrelationJobId = "";
let targetsCache = {};
let correlateInFlight = false;
let importInFlight = false;
let s3ImportInFlight = false;
let importedS3SessionPrefix = "";
let hasLoadedMediaForCorrelation = false;
let logFileOffsets = {};
let lastCapturePreset = null;
let currentEnvironment = "";
let targetsRequestSeq = 0;
let targetsAbortController = null;
let hostSelectionRequestSeq = 0;
let configuredSubRegionsByRegion = {};
let reachabilityRetryTimer = null;
let reachabilityRetryInFlight = false;
let reachabilityCountdownTimer = null;
let reachabilityNextRetryAt = 0;
const REACHABILITY_RETRY_MS = 180000;
let captureConnectivityTimer = null;
let captureConnectivityCheckInFlight = false;
let captureReconnectTimer = null;
let captureReconnectDeadline = 0;
let captureRecovering = false;
let activeCaptureHostIds = [];
let captureReconnectUiTimer = null;
let captureLossUiMode = false;
let captureLossPreviousLogsVisible = true;
let statusClearTimer = null;
let manualStopInProgress = false;
let captureRunning = false;
let leaveStopSent = false;
let pendingLeaveAction = null;
let postCaptureEntryMode = "capture";
let lastStorageNotice = "";
let lastStorageMode = "";
let lastStorageProgressAt = 0;
let lastStorageFlushState = "";
const STORAGE_PROGRESS_INTERVAL_MS = 15000;
let captureAutoRestartInProgress = false;
let lastAutoStopSessionId = "";
let statusPollingFailures = 0;
let statusPollingBackoffMs = 5000;
let statusPollingLastWarnAt = 0;
let s3UploadGateActive = false;
let selectedCaptureStorage = "local";
let selectedS3SpoolDir = "";
const STATUS_POLLING_BASE_MS = 3000;
const STATUS_POLLING_MAX_MS = 60000;
const LIVE_METRICS_INTERVAL_MS = 3000;
const HOST_STALL_MS = 12000;
let lastLiveMetricsUpdateAt = 0;
let hostPacketSnapshot = {};
const CORRELATION_TIMEOUT_MS = 10 * 60 * 1000;

const UI_MODE = Object.freeze({
  IDLE: "idle",
  CAPTURING: "capturing",
  RECOVERING: "recovering",
  POST_CAPTURE: "post_capture",
  CORRELATING: "correlating",
});

let uiMode = UI_MODE.IDLE;

let logEntries = [];
let logSeq = 0;
let logRenderTimer = null;
let logNeedsFullRender = false;
let logWorker = null;
let logWorkerReqSeq = 0;
const logWorkerPending = new Map();
let droppedLogsUnderPressure = 0;
let lastDroppedLogsNoticeAt = 0;
let projectLogPollFailures = 0;
let projectLogPollLastWarnAt = 0;
const MAX_LOG_ENTRIES = 1500;
const MAX_RENDERED_LOG_ENTRIES = 400;
const LOG_PRESSURE_HIGH_WATER = 1000;
const LOG_RENDER_DEBOUNCE_MS = 40;
const LOG_POLL_WARN_INTERVAL_MS = 15000;
const IGNORED_LOG_SUBSTRINGS = [
  "python_multipart.multipart | multipart.py:626",
  "request_logging_middleware() | HTTP request start method=POST path=/api/logs/poll",
  "request_logging_middleware() | HTTP request end method=POST path=/api/logs/poll",
  "path=/api/logs/poll query=",
  "path=/api/logs/poll status=200",
  "request_logging_middleware() | HTTP request start method=GET path=/api/logs/stream",
  "request_logging_middleware() | HTTP request end method=GET path=/api/logs/stream",
  "path=/api/logs/stream query=",
  "path=/api/logs/stream status=200",
];

function fitListSize(count, maxRows = 8) {
  const n = Number(count || 0);
  if (n <= 0) return 1;
  return Math.min(maxRows, Math.max(2, n));
}

function renderSubRegionChips() {
  if (!subRegionChips) return;
  const options = Array.from(subRegionInput.options || []);
  const allSelectedMode = Boolean(allSubRegionsToggle?.checked);
  subRegionChips.innerHTML = "";
  if (!options.length) {
    subRegionChips.innerHTML = '<div class="chip-empty">No sub-regions available.</div>';
    return;
  }
  options.forEach((opt) => {
    const btn = document.createElement("button");
    btn.type = "button";
    const isSelected = allSelectedMode || opt.selected;
    btn.className = `chip-item${isSelected ? " selected" : ""}`;
    btn.innerHTML = `${isSelected ? '<span class="chip-check">✓</span>' : ""}${escapeHtml(opt.value)}`;
    btn.addEventListener("click", () => {
      const wasSelected = Boolean(allSubRegionsToggle.checked || opt.selected);
      if (allSubRegionsToggle.checked) {
        allSubRegionsToggle.checked = false;
        Array.from(subRegionInput.options).forEach((o) => {
          o.selected = true;
        });
      }
      opt.selected = !wasSelected;
      const total = subRegionInput.options.length;
      const selected = subRegionInput.selectedOptions.length;
      allSubRegionsToggle.checked = total > 0 && selected === total;
      renderSubRegionChips();
      updateHostsFromSubRegionSelection();
    });
    subRegionChips.appendChild(btn);
  });
}

function renderHostChips() {
  if (!hostChips) return;
  const options = Array.from(hostInput.options || []);
  const allSelectedMode = Boolean(allHostsToggle?.checked);
  hostChips.innerHTML = "";
  if (!options.length) {
    hostChips.innerHTML = '<div class="chip-empty">No hosts available.</div>';
    return;
  }
  options.forEach((opt) => {
    const btn = document.createElement("button");
    btn.type = "button";
    const isSelected = allSelectedMode || opt.selected;
    btn.className = `chip-item${isSelected ? " selected" : ""}`;
    btn.innerHTML = `${isSelected ? '<span class="chip-check">✓</span>' : ""}${escapeHtml(opt.value)}`;
    btn.addEventListener("click", () => {
      const wasSelected = Boolean(allHostsToggle.checked || opt.selected);
      if (allHostsToggle.checked) {
        allHostsToggle.checked = false;
        hostInput.disabled = false;
        Array.from(hostInput.options).forEach((o) => {
          o.selected = true;
        });
      }
      opt.selected = !wasSelected;
      renderHostChips();
    });
    hostChips.appendChild(btn);
  });
}

function nowIso() {
  return new Date().toISOString();
}

function initLogWorker() {
  if (typeof Worker === "undefined") return;
  try {
    logWorker = new Worker("/static/log_worker.js");
    logWorker.onmessage = (event) => {
      const data = event?.data || {};
      if (data.type !== "parsedProjectLines") return;
      const reqId = Number(data.reqId || 0);
      const resolver = logWorkerPending.get(reqId);
      if (!resolver) return;
      logWorkerPending.delete(reqId);
      resolver(Array.isArray(data.entries) ? data.entries : []);
    };
    logWorker.onerror = () => {
      logWorker = null;
      for (const [, resolver] of logWorkerPending) {
        resolver(null);
      }
      logWorkerPending.clear();
    };
  } catch {
    logWorker = null;
  }
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function highlightLegTokens(escapedText) {
  // Token highlighting is handled centrally in formatStructuredProjectMessage.
  return String(escapedText || "");
}

function shouldDropLogUnderPressure(level, message, source, force = false) {
  if (force) return false;
  const normalized = normalizeLevel(level);
  if (logEntries.length < LOG_PRESSURE_HIGH_WATER) return false;
  if (normalized === "error" || normalized === "warn") return false;
  const src = String(source || "ui");
  const msg = String(message || "");
  if (normalized === "debug") return true;
  if (src === "project" && hasAny(msg.toLowerCase(), ["botocore", "s3transfer", "uploadpart", "http request start", "http request end"])) {
    return true;
  }
  return false;
}

function scheduleLogRender() {
  if (logRenderTimer) return;
  logRenderTimer = setTimeout(() => {
    logRenderTimer = null;
    flushPendingLogRender();
  }, LOG_RENDER_DEBOUNCE_MS);
}

function buildRenderedLogLine(e) {
  const lvl = normalizeLevel(e.level);
  const lineClass = lineLevelClass(lvl);
  const isAlertLevel = lvl === "warn" || lvl === "error";
  if (e.source === "project") {
    let body = isAlertLevel
      ? escapeHtml(e.message)
      : e.structured
        ? formatStructuredProjectMessage(e.message)
        : escapeHtml(e.message);
    if (!isAlertLevel && isLiveStorageMessage(e.message)) {
      body = renderLiveStorageMessage(e.message);
    }
    if (!isAlertLevel) {
      body = highlightLegTokens(body);
    }
    const prefix = bracketPrefix(e.displayTs || e.ts, e.displayLevel || lvl);
    return `<span class="${lineClass}">${prefix}${body}</span>`;
  }
  const prefix = bracketPrefix(e.ts, lvl, true);
  let body = isAlertLevel
    ? escapeHtml(e.message)
    : isLiveStorageMessage(e.message)
      ? renderLiveStorageMessage(e.message)
      : formatStructuredProjectMessage(e.message);
  if (!isAlertLevel) {
    body = highlightLegTokens(body);
  }
  return `<span class="${lineClass}">${prefix}${body}</span>`;
}

function flushPendingLogRender() {
  if (!logNeedsFullRender) return;
  const slice = logEntries.slice(-MAX_RENDERED_LOG_ENTRIES);
  appLog.innerHTML = slice.map((e) => buildRenderedLogLine(e)).join("\n");
  logNeedsFullRender = false;
  appLog.scrollTop = appLog.scrollHeight;
}

function addLog(level, message, meta = {}, options = {}) {
  const msg = String(message || "");
  if (IGNORED_LOG_SUBSTRINGS.some((needle) => msg.includes(needle))) {
    return;
  }
  const source = String(meta.source || "ui");
  const force = Boolean(options.force);
  if (shouldDropLogUnderPressure(level, msg, source, force)) {
    droppedLogsUnderPressure += 1;
    const now = Date.now();
    if ((now - lastDroppedLogsNoticeAt) >= LOG_POLL_WARN_INTERVAL_MS) {
      lastDroppedLogsNoticeAt = now;
      const notice = `High log volume: dropped ${droppedLogsUnderPressure} low-priority log line(s) to keep UI responsive.`;
      droppedLogsUnderPressure = 0;
      addLog("warn", notice, { source: "ui" }, { force: true });
    }
    return;
  }
  const entry = {
    id: ++logSeq,
    ts: nowIso(),
    level,
    message: msg,
    source,
    structured: Boolean(meta.structured),
    displayTs: meta.displayTs ? String(meta.displayTs) : null,
    displayLevel: meta.displayLevel ? String(meta.displayLevel) : null,
    preformattedBody: meta.preformattedBody ? String(meta.preformattedBody) : "",
  };
  logEntries.push(entry);
  if (logEntries.length > MAX_LOG_ENTRIES) {
    const overflow = logEntries.length - MAX_LOG_ENTRIES;
    logEntries.splice(0, overflow);
  }
  logNeedsFullRender = true;
  scheduleLogRender();
}

function hasAny(text, needles) {
  const value = String(text || "");
  return needles.some((needle) => value.includes(needle));
}

function normalizeLevel(level) {
  const lvl = String(level || "").toLowerCase();
  if (lvl === "debug") return "debug";
  if (lvl === "warn" || lvl === "warning") return "warn";
  if (lvl === "error") return "error";
  if (lvl === "notice" || lvl === "info") return "info";
  return "info";
}

function lineLevelClass(level) {
  const lvl = normalizeLevel(level);
  if (lvl === "warn") return "log-line-warn";
  if (lvl === "error") return "log-line-error";
  if (lvl === "info") return "log-line-info";
  return "";
}

function stripStructuredPrefix(line) {
  const s = String(line || "");
  const parts = s.split(" | ");
  if (parts.length >= 7 && /^\d{4}-\d{2}-\d{2}/.test(parts[0])) {
    return parts.slice(6).join(" | ").trim();
  }
  return s.trim();
}

function parseStructuredLine(line) {
  const s = String(line || "");
  const parts = s.split(" | ");
  if (parts.length >= 7 && /^\d{4}-\d{2}-\d{2}/.test(parts[0])) {
    return {
      timestamp: parts[0].trim(),
      level: parts[1].trim().toUpperCase(),
      message: parts.slice(6).join(" | ").trim(),
    };
  }
  return {
    timestamp: null,
    level: null,
    message: s.trim(),
  };
}

function formatStructuredProjectMessage(message) {
  const msg = String(message || "").trim();
  let escaped = escapeHtml(msg);

  const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const colorFieldEquals = (text, fields, cls) => {
    if (!fields.length) return text;
    const names = fields.map(escapeRegex).join("|");
    return text.replace(new RegExp(`(^|[^\\w])(${names})=`, "gi"), (m, prefix, key) => {
      return `${prefix}<span class="${cls}">${key}=</span>`;
    });
  };

  escaped = colorFieldEquals(
    escaped,
    [
      "first_invite_src",
      "first_invite_dst",
      "last_host",
      "carrier",
      "core",
      "request_ip",
      "request_port",
      "reply_ip",
      "reply_port",
      "sip_method_request",
      "sip_method_reply",
      "inline",
      "suite",
    ],
    "log-token-blue"
  );
  escaped = colorFieldEquals(
    escaped,
    [
      "first_invite_packet",
      "analysis_packet",
      "invite_cipher_packet",
      "200ok_cipher_packet",
      "carrier_invite_packet",
      "carrier_200ok_packet",
      "core_invite_packet",
      "invite_packet_number",
      "reply_packet_number",
      "packet_number",
    ],
    "log-token-pink"
  );
  escaped = escaped.replace(
    /\[(media_stream_from_carrier_to_rtpengine|media_stream_from_rtpengine_to_carrier|media_stream_from_rtpengine_to_core|media_stream_from_core_to_rtpengine)\]/gi,
    '<span class="log-token-yellow">[$1]</span>'
  );

  escaped = escaped.replace(/COMBINED FILTER:/gi, '<span class="log-token-green">COMBINED FILTER:</span>');
  escaped = escaped.replace(/(^|[^A-Z])FILTER:/g, (m, prefix) => `${prefix}<span class="log-token-green">FILTER:</span>`);
  escaped = escaped.replace(
    /\b(packets=)(\d+)(\s+KEEP)\b/gi,
    '<span class="log-token-green">$1</span><span class="log-token-value">$2</span><span class="log-token-green">$3</span>'
  );
  escaped = escaped.replace(
    /(combined stream found in file.*)$/gi,
    '<span class="log-token-green">$1</span>'
  );

  return `<span class="log-filter-line">${escaped}</span>`;
}

function bracketPrefix(ts, level, stripZulu = false) {
  let outTs = String(ts || "").trim();
  if (stripZulu && outTs.endsWith("Z")) {
    outTs = outTs.slice(0, -1);
  }
  const outLevel = String(level || "").trim().toUpperCase();
  if (outTs && outLevel) return `[${escapeHtml(outTs)}] [${escapeHtml(outLevel)}] `;
  return "";
}

function isLiveStorageMessage(message) {
  const msg = String(message || "");
  return msg.startsWith("Capturing and saving to S3 bucket") || msg.startsWith("Capturando e salvando para");
}

function renderLiveStorageMessage(message) {
  return `<span class="log-live-storage">${escapeHtml(message)}</span>`;
}

function renderAppLog() {
  logNeedsFullRender = true;
  scheduleLogRender();
}

function serverLineToLevel(line) {
  const s = String(line || "");
  if (s.startsWith("ERROR:")) return "error";
  if (s.startsWith("WARN:")) return "warn";
  if (s.startsWith("DEBUG:")) return "debug";
  if (s.startsWith("NOTICE:")) return "notice";
  return "notice";
}

function logLevelFromStructuredLine(line) {
  const s = String(line || "");
  const m = s.match(/\|\s(DEBUG|INFO|NOTICE|WARNING|ERROR)\s\|/i);
  if (!m) return "info";
  const lvl = m[1].toUpperCase();
  if (lvl === "DEBUG") return "debug";
  if (lvl === "WARNING") return "warn";
  if (lvl === "ERROR") return "error";
  return "info";
}

function logServerLines(lines) {
  const raw = Array.isArray(lines) ? lines : [];
  raw.forEach((line) => addLog(serverLineToLevel(line), line));
}

async function parseProjectLogLines(lines) {
  if (!Array.isArray(lines) || !lines.length) return [];
  if (!logWorker) {
    return lines.map((ln) => {
      const parsed = parseStructuredLine(ln);
      return {
        level: logLevelFromStructuredLine(ln),
        message: parsed.message || stripStructuredPrefix(ln),
        displayTs: parsed.timestamp || null,
        displayLevel: parsed.level || null,
        structured: true,
        preformattedBody: formatStructuredProjectMessage(parsed.message || stripStructuredPrefix(ln)),
      };
    });
  }
  const reqId = ++logWorkerReqSeq;
  const parsed = await new Promise((resolve) => {
    logWorkerPending.set(reqId, resolve);
    try {
      logWorker.postMessage({ type: "parseProjectLines", reqId, lines });
    } catch {
      logWorkerPending.delete(reqId);
      resolve(null);
    }
  });
  if (!Array.isArray(parsed)) {
    return lines.map((ln) => {
      const parsedLine = parseStructuredLine(ln);
      return {
        level: logLevelFromStructuredLine(ln),
        message: parsedLine.message || stripStructuredPrefix(ln),
        displayTs: parsedLine.timestamp || null,
        displayLevel: parsedLine.level || null,
        structured: true,
        preformattedBody: formatStructuredProjectMessage(parsedLine.message || stripStructuredPrefix(ln)),
      };
    });
  }
  return parsed;
}

async function ingestProjectLogChunks(files) {
  (files || []).forEach((item) => {
    const name = String(item.name || "");
    const text = String(item.text || "");
    const size = Number(item.size || 0);
    if (!name) return;

    if (text) {
      const lines = text
        .split(/\r?\n/)
        .filter((ln) => ln.trim().length);
      void parseProjectLogLines(lines).then((parsedItems) => {
        parsedItems.forEach((itemLine) => {
          addLog(itemLine.level || "info", itemLine.message || "", {
            source: "project",
            structured: true,
            displayTs: itemLine.displayTs || null,
            displayLevel: itemLine.displayLevel || null,
            preformattedBody: itemLine.preformattedBody || "",
          });
        });
      });
    }
    logFileOffsets[name] = size;
  });
}

async function pollProjectLogs() {
  try {
    const data = await api("/api/logs/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ offsets: logFileOffsets }),
    });
    ingestProjectLogChunks(data.files || []);
    if (projectLogPollFailures > 0) {
      addLog("info", "Live log polling recovered.");
    }
    projectLogPollFailures = 0;
    projectLogPollLastWarnAt = 0;
  } catch (err) {
    projectLogPollFailures += 1;
    const now = Date.now();
    if (
      projectLogPollFailures <= 2 ||
      (now - projectLogPollLastWarnAt) >= LOG_POLL_WARN_INTERVAL_MS
    ) {
      addLog("warn", `Project live log update failed: ${err.message}`);
      projectLogPollLastWarnAt = now;
    }
  }
}

async function pollProjectLogsForced() {
  try {
    const data = await api("/api/logs/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ offsets: logFileOffsets }),
    });
    ingestProjectLogChunks(data.files || []);
    projectLogPollFailures = 0;
    projectLogPollLastWarnAt = 0;
  } catch {
    // keep silent during forced polling
  }
}

function sleepWithAbort(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      cleanup();
      reject(new DOMException("Aborted", "AbortError"));
    };
    const cleanup = () => {
      if (signal) {
        signal.removeEventListener("abort", onAbort);
      }
    };
    if (signal) {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

function startCorrelationLiveLogPolling() {
  if (typeof EventSource !== "undefined") {
    startLogStreaming();
  }
  if (logEventSource) {
    return;
  }
  if (logPollTimer) {
    // Polling fallback is already running.
    return;
  }
  if (correlationLiveLogTimer) clearInterval(correlationLiveLogTimer);
  pollProjectLogsForced();
  correlationLiveLogTimer = setInterval(pollProjectLogsForced, 2000);
}

function stopCorrelationLiveLogPolling() {
  if (correlationLiveLogTimer) {
    clearInterval(correlationLiveLogTimer);
    correlationLiveLogTimer = null;
  }
}

async function waitForCorrelationJob(jobId, options = {}) {
  const timeoutMs = Number(options.timeoutMs || CORRELATION_TIMEOUT_MS);
  const signal = options.signal || null;
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
  const onEvents = typeof options.onEvents === "function" ? options.onEvents : null;
  const startedAt = Date.now();
  const encoded = encodeURIComponent(jobId);
  let eventsCursor = 0;

  const pullEvents = async () => {
    if (!onEvents) return;
    const payload = await api(`/api/jobs/${encoded}/events?after_seq=${eventsCursor}`, { signal });
    const events = Array.isArray(payload?.events) ? payload.events : [];
    if (!events.length) return;
    eventsCursor = Number(events[events.length - 1].seq || eventsCursor);
    onEvents(events);
  };

  while (true) {
    if (signal?.aborted) {
      throw new DOMException("Aborted", "AbortError");
    }
    if ((Date.now() - startedAt) > timeoutMs) {
      throw new Error(`Correlation timed out after ${Math.round(timeoutMs / 1000)}s`);
    }
    await pullEvents();
    const status = await api(`/api/jobs/${encoded}`, { signal });
    if (status.status === "queued" || status.status === "running") {
      if (onProgress) {
        onProgress({
          status,
          elapsedMs: Date.now() - startedAt,
        });
      }
      await sleepWithAbort(1000, signal);
      continue;
    }
    if (status.status === "canceled" || status.status === "cancelled" || status.status === "cancel_requested") {
      throw new Error("Correlation canceled");
    }
    if (status.status === "failed") {
      await pullEvents();
      throw new Error(status.error || "Correlation job failed");
    }
    if (status.status === "completed") {
      await pullEvents();
      const result = await api(`/api/jobs/${encoded}/result`, { signal });
      return result.result || {};
    }
    throw new Error(`Unexpected correlation job status: ${status.status || "unknown"}`);
  }
}

function startLogPolling() {
  if (logPollTimer) clearInterval(logPollTimer);
  logPollTimer = setInterval(pollProjectLogs, 2000);
}

function stopLogStreaming() {
  if (!logEventSource) return;
  try {
    logEventSource.close();
  } catch {
    // ignore close errors
  }
  logEventSource = null;
}

function startLogStreaming() {
  if (typeof EventSource === "undefined") {
    startLogPolling();
    return;
  }
  if (logEventSource) return;
  if (logPollTimer) {
    clearInterval(logPollTimer);
    logPollTimer = null;
  }
  const stream = new EventSource("/api/logs/stream");
  logEventSource = stream;
  stream.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data || "{}");
      ingestProjectLogChunks(data.files || []);
    } catch {
      // ignore malformed stream chunk
    }
  };
  stream.onerror = () => {
    stopLogStreaming();
    startLogPolling();
  };
}

async function initializeLogOffsetsFromCurrentFiles() {
  // Establish a baseline so the panel only shows logs generated after this UI session starts.
  const data = await api("/api/logs/poll", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ offsets: {} }),
  });
  (data.files || []).forEach((item) => {
    const name = String(item.name || "");
    const size = Number(item.size || 0);
    if (name) {
      logFileOffsets[name] = size;
    }
  });
}

function setUiMode(mode) {
  uiMode = Object.values(UI_MODE).includes(mode) ? mode : UI_MODE.IDLE;
  document.body.dataset.uiMode = uiMode;
}

function setCriticalStatus(message, isError = true) {
  if (!criticalStatusBox) return;
  const msg = String(message || "").trim();
  if (!msg) {
    criticalStatusBox.hidden = true;
    criticalStatusBox.textContent = "";
    criticalStatusBox.className = "status status-critical";
    return;
  }
  criticalStatusBox.hidden = false;
  criticalStatusBox.textContent = msg;
  criticalStatusBox.className = isError ? "status status-critical error" : "status status-critical";
}

function setStatus(message, isError = false) {
  const msg = String(message || "");
  const showSpinner = /^Attempting to re-establish capture/i.test(msg);
  if (showSpinner) {
    statusBox.innerHTML = '<span class="status-inline-spinner" aria-hidden="true"></span>' + escapeHtml(msg);
  } else {
    statusBox.textContent = msg;
  }
  statusBox.className = isError ? "status error" : "status";
}

function setLiveMetrics(message) {
  if (!counterBox) return;
  counterBox.textContent = String(message || "");
}

function setLiveMetricsThrottled(message, force = false) {
  const now = Date.now();
  if (!force && now - lastLiveMetricsUpdateAt < LIVE_METRICS_INTERVAL_MS) return;
  lastLiveMetricsUpdateAt = now;
  setLiveMetrics(message);
}

function resetHostConnectivityState() {
  hostPacketSnapshot = {};
}

function updateHostConnectivityState(counts) {
  if (!captureRunning) {
    resetHostConnectivityState();
    return;
  }
  const now = Date.now();
  const hostIds = new Set([
    ...Object.keys(hostPacketSnapshot || {}),
    ...Object.keys(counts || {}).filter((host) => host !== "total"),
    ...(Array.isArray(activeCaptureHostIds) ? activeCaptureHostIds : []),
  ]);
  hostIds.forEach((hostId) => {
    const current = Number(counts?.[hostId] || 0);
    const prev = hostPacketSnapshot[hostId];
    if (!prev || current > Number(prev.count || 0)) {
      if (prev?.stalled) {
        setTransientStatus(`Connection to host ${hostId} restored. Capture is running.`, false, 5000, "Capture running.");
        addLog("info", `Host connection restored host=${hostId}`);
      }
      hostPacketSnapshot[hostId] = { count: current, lastAdvanceAt: now, stalled: false };
      return;
    }
    const lastAdvanceAt = Number(prev.lastAdvanceAt || now);
    const hasSeenTraffic = Number(prev.count || 0) > 0 || current > 0;
    const stalled = hasSeenTraffic && (now - lastAdvanceAt) >= HOST_STALL_MS;
    if (stalled && !prev.stalled) {
      setTransientStatus(
        `Connection to host ${hostId} appears lost (no packets for ${Math.round(HOST_STALL_MS / 1000)}s). Capture continues.`,
        true,
        5000,
        "Capture running."
      );
      addLog("warn", `Host connection lost host=${hostId} no_packets_for_s=${Math.round(HOST_STALL_MS / 1000)}`);
    }
    hostPacketSnapshot[hostId] = { count: current, lastAdvanceAt, stalled };
  });
}

function setTransientStatus(message, isError = false, durationMs = 4000, replacement = "") {
  setStatus(message, isError);
  if (statusClearTimer) {
    clearTimeout(statusClearTimer);
    statusClearTimer = null;
  }
  statusClearTimer = setTimeout(() => {
    setStatus(replacement, false);
    statusClearTimer = null;
  }, durationMs);
}

function handleStorageNotice(notice, level = "warn") {
  const text = String(notice || "").trim();
  if (!text || text === lastStorageNotice) return;
  lastStorageNotice = text;
  addLog(level, text);
  setTransientStatus(text, false, 6000, captureRunning ? "Capture running." : "Ready.");
}

function handleStorageState(storageMode, notice, storageTarget = "") {
  const mode = String(storageMode || "").trim().toLowerCase();
  handleStorageNotice(notice, "warn");
  updateCaptureStorageHint(mode, storageTarget);
  if (mode === "s3" && mode !== lastStorageMode) {
    addLog("info", "S3 storage active. Capture files are being written to Amazon S3.");
  }
  if (mode) {
    lastStorageMode = mode;
  }
  maybeLogStorageProgress(mode, storageTarget);
}

function applyStorageFlushState(flush) {
  if (!flush || typeof flush !== "object") {
    setS3UploadGate(false, 0);
    updateCorrelationUiState();
    return;
  }
  const state = String(flush.state || "").trim().toLowerCase();
  const pending = Number(flush.pending_files || 0);
  const failedFiles = Number(flush.failed_files || 0);
  const errorText = String(flush.error || "").trim();
  const currentFile = String(flush.current_file || "").trim();
  const gateActive =
    state === "queued" ||
    state === "running" ||
    ((state === "paused" || state === "failed") && (pending > 0 || failedFiles > 0));
  setS3UploadGate(gateActive, pending > 0 ? pending : failedFiles);
  const signature = `${state}:${pending}:${errorText}`;
  if (signature === lastStorageFlushState) return;
  lastStorageFlushState = signature;
  if (gateActive) {
    if (rawFiles) {
      rawFiles.innerHTML = "";
    }
    hasLoadedMediaForCorrelation = false;
    const suffix = pending > 0 ? ` pending files=${pending}` : "";
    if (errorText) {
      const normalizedReason = errorText.replace(/\s*after flush attempt\s*/i, "").trim();
      const uploadMsg = `Uploading file to S3. flush=${normalizedReason}`;
      setStatus(uploadMsg);
      addLog("warn", uploadMsg);
    } else {
      setStatus(`Capture stopped. Finalizing S3 uploads in background...${suffix}`);
      addLog("info", `Finalizing S3 uploads in background state=${state}${suffix}`);
    }
    updateCorrelationUiState();
    return;
  }
  if (state === "completed") {
    setStatus("Capture stopped.");
    addLog("info", "S3 copy completed successfully.");
    addLog("info", "S3 final upload flush completed.");
    void refreshRawFilesFromLatestSession();
    updateCorrelationUiState();
    return;
  }
  if (state === "fallback_local") {
    setStatus("Capture stopped. S3 finalization failed and switched to local storage.", true);
    addLog("warn", "S3 final upload flush failed and switched to local storage.");
    updateCorrelationUiState();
    return;
  }
  if (state === "paused") {
    const msg = errorText || "S3 flush paused by user.";
    setStatus(msg, true);
    addLog("warn", msg);
    updateCorrelationUiState();
    return;
  }
  if (state === "failed") {
    const msg = errorText || "S3 flush failed after maximum retries.";
    setStatus(msg, true);
    addLog("error", msg);
    updateCorrelationUiState();
    return;
  }
  updateCorrelationUiState();
}

function isStorageFlushActive(flush) {
  if (!flush || typeof flush !== "object") return false;
  const state = String(flush.state || "").trim().toLowerCase();
  const pending = Number(flush.pending_files || 0);
  const failedFiles = Number(flush.failed_files || 0);
  if (state === "queued" || state === "running") return true;
  if ((state === "paused" || state === "failed") && (pending > 0 || failedFiles > 0)) return true;
  return false;
}

function maybeLogStorageProgress(storageMode, storageTarget) {
  if (!captureRunning) return;
  const now = Date.now();
  if ((now - lastStorageProgressAt) < STORAGE_PROGRESS_INTERVAL_MS) return;
  const mode = String(storageMode || "").trim().toLowerCase();
  const target = String(storageTarget || "").trim();
  if (mode === "s3") {
    addLog("info", `Capturing and saving to S3 bucket ${target || "(default path)"}`);
    lastStorageProgressAt = now;
    return;
  }
  if (mode === "local") {
    addLog("info", `Capturando e salvando para ${target || "(local path)"}`);
    lastStorageProgressAt = now;
  }
}

function setRegionStatus(message, isError = false) {
  if (!regionStatus) return;
  regionStatus.textContent = String(message || "");
  regionStatus.className = isError ? "help error" : "help";
}

function setSubRegionStatus(message, isError = false) {
  if (!subRegionStatus) return;
  const text = String(message || "");
  subRegionStatus.textContent = text;
  subRegionStatus.className = isError ? "help error" : "help";
  const loading = !isError && /^Testing RTPEngine reachability/i.test(text);
  subRegionStatus.classList.toggle("subregion-status-loading", loading);
}

function stopReachabilityAutoRetry() {
  if (reachabilityRetryTimer) {
    clearInterval(reachabilityRetryTimer);
    reachabilityRetryTimer = null;
  }
  if (reachabilityCountdownTimer) {
    clearInterval(reachabilityCountdownTimer);
    reachabilityCountdownTimer = null;
  }
  reachabilityNextRetryAt = 0;
}

function formatReachabilityCountdown() {
  const remainingMs = Math.max(0, reachabilityNextRetryAt - Date.now());
  const totalSeconds = Math.ceil(remainingMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function updateReachabilityAutoInfo() {
  if (!noReachableAutoInfo) return;
  if (!reachabilityNextRetryAt) {
    noReachableAutoInfo.textContent = "";
    return;
  }
  noReachableAutoInfo.textContent = `Automatic reachability test in ${formatReachabilityCountdown()}`;
}

function hideNoReachablePanel() {
  if (noReachablePanel) {
    noReachablePanel.hidden = true;
  }
  if (noReachableMessage) {
    noReachableMessage.textContent = "";
  }
  stopReachabilityAutoRetry();
  updateReachabilityAutoInfo();
  setCriticalStatus("");
}

function setCaptureLossUiMode(enabled) {
  const next = Boolean(enabled);
  if (next === captureLossUiMode) return;
  captureLossUiMode = next;
  if (captureLossUiMode) {
    setUiMode(UI_MODE.RECOVERING);
    captureLossPreviousLogsVisible = !logSection.hidden;
    homePanel.hidden = true;
    environmentPanel.hidden = true;
    captureFlowPanel.hidden = true;
    subRegionFlowPanel.hidden = true;
    hostPanel.hidden = true;
    livePanel.hidden = true;
    postSection.hidden = true;
    logSection.hidden = true;
    return;
  }
  if (captureRunning) {
    setUiMode(UI_MODE.CAPTURING);
  }
  logSection.hidden = !captureLossPreviousLogsVisible;
}

function showNoReachablePanel(region, options = {}) {
  const hideCapturePanels = Boolean(options.hideCapturePanels);
  if (noReachablePanel) {
    noReachablePanel.hidden = false;
  }
  if (noReachableMessage) {
    noReachableMessage.textContent = `Could not connect to RTPEngine in region ${region}`;
  }
  setCriticalStatus(`Could not connect to RTPEngine in region ${region}`, true);
  if (hideCapturePanels) {
    captureFlowPanel.hidden = true;
    subRegionFlowPanel.hidden = true;
    hostPanel.hidden = true;
    livePanel.hidden = true;
  }
  reachabilityNextRetryAt = Date.now() + REACHABILITY_RETRY_MS;
  updateReachabilityAutoInfo();
  if (!reachabilityCountdownTimer) {
    reachabilityCountdownTimer = setInterval(updateReachabilityAutoInfo, 1000);
  }
  if (!reachabilityRetryTimer) {
    reachabilityRetryTimer = setInterval(() => {
      if (reachabilityRetryInFlight) return;
      reachabilityNextRetryAt = Date.now() + REACHABILITY_RETRY_MS;
      updateReachabilityAutoInfo();
      updateHostsFromSubRegionSelection({ autoRetry: true });
    }, REACHABILITY_RETRY_MS);
  }
}

function stopCaptureConnectivityMonitor() {
  if (captureConnectivityTimer) {
    clearInterval(captureConnectivityTimer);
    captureConnectivityTimer = null;
  }
  captureConnectivityCheckInFlight = false;
}

function stopCaptureReconnectWindow() {
  if (captureReconnectTimer) {
    clearInterval(captureReconnectTimer);
    captureReconnectTimer = null;
  }
  if (captureReconnectUiTimer) {
    clearInterval(captureReconnectUiTimer);
    captureReconnectUiTimer = null;
  }
  captureReconnectDeadline = 0;
  captureRecovering = false;
  if (captureRecoveryPanel) captureRecoveryPanel.hidden = true;
  captureLossUiMode = false;
}

function updateCaptureRecoveryUi() {
  if (!captureRecoveryPanel || !captureRecoveryCountdown || !captureRecoveryProgress) return;
  if (!captureReconnectDeadline) {
    captureRecoveryPanel.hidden = true;
    return;
  }
  const total = 60000;
  const remainingMs = Math.max(0, captureReconnectDeadline - Date.now());
  const remainingSec = Math.ceil(remainingMs / 1000);
  const pct = Math.max(0, Math.min(100, (remainingMs / total) * 100));
  captureRecoveryPanel.hidden = false;
  captureRecoveryCountdown.textContent = `Attempting automatic reconnect in ${remainingSec}s`;
  captureRecoveryProgress.style.width = `${pct}%`;
}

function flattenReachableHostIds(targetsPayload, region, selectedSubRegions) {
  const reachable = targetsPayload && typeof targetsPayload === "object" ? targetsPayload.reachable : null;
  const regionMap = reachable && typeof reachable === "object" ? reachable[region] : null;
  if (!regionMap || typeof regionMap !== "object") return new Set();
  const wanted = new Set(Array.isArray(selectedSubRegions) ? selectedSubRegions : []);
  const all = new Set();
  Object.entries(regionMap).forEach(([subRegion, hosts]) => {
    if (wanted.size && !wanted.has(subRegion)) return;
    if (!Array.isArray(hosts)) return;
    hosts.forEach((h) => {
      if (h && typeof h === "object" && h.id) {
        all.add(String(h.id));
      }
    });
  });
  return all;
}

function looksLikeConnectivityFailure(reason) {
  const text = String(reason || "").toLowerCase();
  if (!text) return false;
  return (
    text.includes("connect") ||
    text.includes("connection") ||
    text.includes("timeout") ||
    text.includes("unreachable") ||
    text.includes("rpcap")
  );
}

function connectivityTargetsFromPreset() {
  const preset = lastCapturePreset || {};
  const environment = String(preset.environment || environmentInput.value || "").toUpperCase();
  const region = String(preset.region || regionInput.value || "").trim();
  const subRegions = Array.isArray(preset.subRegions) ? preset.subRegions.filter(Boolean) : [];
  const requiredHosts = (Array.isArray(activeCaptureHostIds) && activeCaptureHostIds.length)
    ? activeCaptureHostIds.slice()
    : (Array.isArray(preset.hostIds) ? preset.hostIds.filter(Boolean) : []);
  return { environment, region, subRegions, requiredHosts };
}

async function isCaptureConnectivityHealthy() {
  const { environment, region, subRegions, requiredHosts } = connectivityTargetsFromPreset();
  if (!environment || !region) return true;
  const qs = new URLSearchParams({ environment, region, refresh: "true" });
  const data = await api(`/api/targets?${qs.toString()}`);
  const reachableHostIds = flattenReachableHostIds(data, region, subRegions);
  if (requiredHosts.length) {
    return requiredHosts.every((id) => reachableHostIds.has(String(id)));
  }
  return reachableHostIds.size > 0;
}

async function restartCaptureFromPresetAfterRecovery() {
  const preset = lastCapturePreset;
  if (!preset) return false;
  captureAutoRestartInProgress = true;
  updateStartCaptureAvailability();
  setCaptureLossUiMode(false);
  // Restore capture panels immediately when connectivity comes back.
  hideNoReachablePanel();
  if (captureRecoveryPanel) captureRecoveryPanel.hidden = true;
  homePanel.hidden = true;
  environmentPanel.hidden = false;
  captureFlowPanel.hidden = false;
  subRegionFlowPanel.hidden = false;
  hostPanel.hidden = false;
  livePanel.hidden = false;
  postSection.hidden = true;
  setStatus("Attempting to re-establish capture...");

  const payload = {
    environment: String(preset.environment || "").toUpperCase(),
    region: String(preset.region || ""),
    sub_regions: Array.isArray(preset.subRegions) ? preset.subRegions.slice() : [],
    host_ids: Boolean(preset.allHosts) ? [] : (Array.isArray(preset.hostIds) ? preset.hostIds.slice() : []),
    filter: String(preset.filter || ""),
    output_dir_name: String(preset.outputDirName || ""),
    storage_location: String(preset.storageLocation || "local"),
    s3_spool_dir: String(preset.s3SpoolDir || ""),
    timeout_minutes: Number.isInteger(Number(preset.timeoutMinutes)) && Number(preset.timeoutMinutes) > 0
      ? Number(preset.timeoutMinutes)
      : null,
    resume_session_id: String(preset.sessionId || ""),
  };
  try {
    const data = await api("/api/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    activeCaptureHostIds = Array.isArray(data.hosts) ? data.hosts.slice() : [];
    if (lastCapturePreset) {
      lastCapturePreset.sessionId = data.session_id;
    }
    lastAutoStopSessionId = "";
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    setCaptureUiRunning(true);
    setUiMode(UI_MODE.CAPTURING);
    postSection.hidden = true;
    setCriticalStatus(`Active capture running in ${data.environment}/${data.region}. Leaving this page will cancel the capture.`, false);
    setTransientStatus("Connectivity restored. Capture restarted automatically.", false, 4500, "Capture running.");
    addLog(
      "info",
      `Capture restarted after connectivity recovery session_id=${data.session_id} region=${data.region} hosts=${activeCaptureHostIds.length ? activeCaptureHostIds.join(",") : "(all)"}`
    );
    startStatusPolling();
    return true;
  } catch (err) {
    setStatus(`Could not re-establish capture: ${err.message || err}`, true);
    addLog("error", `Automatic capture restart failed: ${err.message || err}`);
    return false;
  } finally {
    captureAutoRestartInProgress = false;
    updateStartCaptureAvailability();
  }
}

async function onCaptureConnectivityLost() {
  if (manualStopInProgress) return;
  if (captureRecovering) return;
  captureRecovering = true;
  setUiMode(UI_MODE.RECOVERING);
  updateStartCaptureAvailability();
  stopCaptureConnectivityMonitor();
  addLog("warn", "Media server connectivity lost during active capture. Stopping capture and preserving files.");
  setCaptureLossUiMode(true);

  // Show connectivity panels immediately, without waiting for stop response.
  showNoReachablePanel(String(lastCapturePreset?.region || regionInput.value || "-"), { hideCapturePanels: true });
  captureReconnectDeadline = Date.now() + 60000;
  updateCaptureRecoveryUi();
  if (captureReconnectUiTimer) clearInterval(captureReconnectUiTimer);
  captureReconnectUiTimer = setInterval(updateCaptureRecoveryUi, 1000);

  try {
    const data = await api("/api/capture/stop", { method: "POST" });
    setCaptureUiRunning(false);
    postSection.hidden = true;
    renderRawFiles(data.raw_files, data.raw_dir, data.storage_mode, data.storage_target);
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    setStatus("Capture stopped due to connectivity loss. Files were saved.");
  } catch (err) {
    addLog("error", `Automatic stop after connectivity loss failed: ${err.message || err}`);
  }
  if (captureReconnectTimer) clearInterval(captureReconnectTimer);
  captureReconnectTimer = setInterval(async () => {
    if (captureConnectivityCheckInFlight) return;
    captureConnectivityCheckInFlight = true;
    try {
      if (Date.now() >= captureReconnectDeadline) {
        if (captureReconnectTimer) {
          clearInterval(captureReconnectTimer);
          captureReconnectTimer = null;
        }
        if (captureReconnectUiTimer) {
          clearInterval(captureReconnectUiTimer);
          captureReconnectUiTimer = null;
        }
        captureReconnectDeadline = 0;
        captureRecovering = false;
        updateStartCaptureAvailability();
        if (captureRecoveryPanel) captureRecoveryPanel.hidden = false;
        if (captureRecoveryCountdown) {
          captureRecoveryCountdown.textContent = "Automatic reconnect window expired. Waiting for connectivity.";
        }
        if (captureRecoveryProgress) {
          captureRecoveryProgress.style.width = "0%";
        }
        addLog("warn", "Connectivity did not recover within 60 seconds. Automatic restart skipped.");
        return;
      }
      const healthy = await isCaptureConnectivityHealthy();
      if (!healthy) return;
      stopCaptureReconnectWindow();
      await restartCaptureFromPresetAfterRecovery();
      startCaptureConnectivityMonitor();
    } catch (err) {
      addLog("warn", `Connectivity recovery check failed: ${err.message || err}`);
    } finally {
      captureConnectivityCheckInFlight = false;
    }
  }, 5000);
}

function startCaptureConnectivityMonitor() {
  // Intentionally disabled during active capture:
  // reachability probes can conflict with rpcapd capture sockets on some hosts.
  stopCaptureConnectivityMonitor();
}

async function cancelActiveCaptureForNavigation() {
  if (!captureRunning || manualStopInProgress) return true;
  manualStopInProgress = true;
  stopCaptureRuntimeForLeave();
  try {
    await api("/api/capture/stop-safe", { method: "POST" });
    setCaptureUiRunning(false);
    activeCaptureHostIds = [];
    setStatus("Capture cancelled.");
    return true;
  } catch (err) {
    setStatus(`Failed to cancel capture before leaving: ${err.message || err}`, true);
    addLog("error", `Failed to cancel active capture before leaving: ${err.message || err}`);
    return false;
  } finally {
    manualStopInProgress = false;
  }
}

function setLogsVisible(visible) {
  logSection.hidden = !visible;
  showLogsToggle.textContent = visible ? "Hide Logs" : "Show Logs";
}

function setCorrelationProgress(visible) {
  if (!correlateProgress) return;
  correlateProgress.hidden = !visible;
  if (cancelCorrelationBtn) {
    cancelCorrelationBtn.disabled = !visible;
  }
}

function updateStartCaptureAvailability() {
  const locked =
    uiMode === UI_MODE.CAPTURING ||
    uiMode === UI_MODE.RECOVERING ||
    uiMode === UI_MODE.CORRELATING ||
    captureRunning ||
    captureAutoRestartInProgress ||
    captureRecovering;
  startBtn.disabled = locked;
}

function updatePostCaptureActionLabel() {
  if (!restartCaptureBtn) return;
  restartCaptureBtn.textContent = postCaptureEntryMode === "process" ? "▶️ Start Media Capture" : "🔁 Restart Capture";
}

function setPostCaptureEntryMode(mode) {
  postCaptureEntryMode = mode === "process" ? "process" : "capture";
  updatePostCaptureActionLabel();
  if (mediaSourcePanel) {
    mediaSourcePanel.hidden = postCaptureEntryMode !== "process";
  }
  if (postCaptureEntryMode !== "process" && s3ImportPanel) {
    s3ImportPanel.hidden = true;
  }
}

function setMediaSourceStatus(message, isError = false) {
  if (!mediaSourceStatus) return;
  mediaSourceStatus.textContent = String(message || "");
  mediaSourceStatus.className = isError ? "help error" : "help";
}

function setS3UploadGate(active, pending = 0) {
  s3UploadGateActive = Boolean(active);
  if (s3FlushNotice) {
    s3FlushNotice.hidden = !s3UploadGateActive;
  }
  if (!s3FlushNoticeText) return;
  if (s3UploadGateActive) {
    const suffix = Number(pending) > 0 ? ` Pending files: ${Number(pending)}.` : "";
    s3FlushNoticeText.textContent = `Writing media files to S3 bucket. Correlation will be enabled when upload completes.${suffix}`;
    return;
  }
  s3FlushNoticeText.textContent = "Writing media files to S3 bucket. Correlation will be enabled when upload completes.";
}

async function stopStorageFlush() {
  try {
    if (stopFlushBtn) stopFlushBtn.disabled = true;
    const payload = {};
    if (lastCapturePreset?.sessionId) {
      payload.session_id = String(lastCapturePreset.sessionId);
    }
    const data = await api("/api/storage/flush/stop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    applyStorageFlushState(data.storage_flush || {});
    const pending = Number(data?.storage_flush?.pending_files || 0);
    const tmpDir = String(data?.local_tmp_dir || data?.storage_flush?.tmp_root || "").trim() || "(unknown)";
    const guidance =
      "S3 flush is paused. Some media files are still on local disk. " +
      `Local temporary directory: ${tmpDir}. ` +
      "To correlate SIP flow, either finish S3 flush first or download the files already uploaded to S3 before running correlation.";
    setStatus(guidance, pending > 0);
    addLog("warn", `S3 flush stopped by user for session ${String(data.session_id || "-")}.`);
    addLog("warn", guidance);
  } catch (err) {
    addLog("error", `Could not stop S3 flush: ${err.message || err}`);
    setStatus(`Could not stop S3 flush: ${err.message || err}`, true);
  } finally {
    if (stopFlushBtn) stopFlushBtn.disabled = false;
  }
}

async function resumeStorageFlush() {
  const sessionId = prompt("Enter session id to resume S3 flush:");
  if (!sessionId || !String(sessionId).trim()) return;
  try {
    if (resumeFlushBtn) resumeFlushBtn.disabled = true;
    const data = await api("/api/storage/flush/resume", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: String(sessionId).trim() }),
    });
    applyStorageFlushState(data.storage_flush || {});
    addLog("info", `S3 flush resumed for session ${String(data.session_id || "-")}.`);
  } catch (err) {
    addLog("error", `Could not resume S3 flush: ${err.message || err}`);
    setStatus(`Could not resume S3 flush: ${err.message || err}`, true);
  } finally {
    if (resumeFlushBtn) resumeFlushBtn.disabled = false;
  }
}

function setS3ImportStatus(message, isError = false) {
  if (!s3ImportStatus) return;
  s3ImportStatus.textContent = String(message || "");
  s3ImportStatus.className = isError ? "help error" : "help";
}

function formatBytes(n) {
  const bytes = Number(n || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

async function refreshS3Sessions(revealPanel = true) {
  if (!s3ImportPanel || !s3SessionSelect) return;
  if (s3ImportInFlight) return;
  try {
    s3ImportInFlight = true;
    refreshS3SessionsBtn.disabled = true;
    importS3SessionBtn.disabled = true;
    setS3ImportStatus("Loading S3 sessions...");
    const data = await api("/api/s3/sessions");
    const sessions = Array.isArray(data.sessions) ? data.sessions : [];
    s3SessionSelect.innerHTML = '<option value="">Select S3 session...</option>';
    sessions.forEach((s) => {
      const opt = document.createElement("option");
      const prefix = String(s.session_prefix || "");
      const env = String(s.environment || "-");
      const sid = String(s.session_id || "-");
      const files = Number(s.files || 0);
      const size = formatBytes(Number(s.bytes || 0));
      const out = String(s.output_dir || "");
      opt.value = prefix;
      opt.textContent = `${env} | ${out ? `${out}/` : ""}${sid} | files=${files} | size=${size}`;
      s3SessionSelect.appendChild(opt);
    });
    if (revealPanel) {
      s3ImportPanel.hidden = false;
    }
    if (!sessions.length) {
      setS3ImportStatus("No S3 capture sessions found under misc/captures.");
      return;
    }
    setS3ImportStatus(`Loaded ${sessions.length} S3 session(s).`);
  } catch (err) {
    if (revealPanel) {
      s3ImportPanel.hidden = true;
    }
    setS3ImportStatus("");
    const msg = String(err?.message || err || "S3 storage mode is disabled");
    if (msg.toLowerCase().includes("s3 storage mode is disabled")) {
      addLog("info", "S3 storage mode is disabled");
    } else {
      addLog("warn", msg);
    }
  } finally {
    s3ImportInFlight = false;
    refreshS3SessionsBtn.disabled = false;
    importS3SessionBtn.disabled = false;
  }
}

async function importSelectedS3Session() {
  if (!s3SessionSelect) return;
  const sessionPrefix = String(s3SessionSelect.value || "").trim();
  if (!sessionPrefix) {
    setS3ImportStatus("Select an S3 session first.", true);
    return;
  }
  if (importInFlight || s3ImportInFlight) return;
  try {
    importInFlight = true;
    s3ImportInFlight = true;
    processBtn.disabled = true;
    refreshS3SessionsBtn.disabled = true;
    importS3SessionBtn.disabled = true;
    setS3ImportStatus("Importing selected S3 session...");
    addLog("info", `Importing media from S3 session ${sessionPrefix}`);
    const data = await api("/api/s3/import-session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_prefix: sessionPrefix,
        output_dir_name: outputDirNameInput?.value || "",
      }),
    });
    addLog("info", `S3 media import completed session_id=${data.session_id}`);
    homePanel.hidden = true;
    environmentPanel.hidden = true;
    captureFlowPanel.hidden = true;
    subRegionFlowPanel.hidden = true;
    hideNoReachablePanel();
    hostPanel.hidden = true;
    livePanel.hidden = true;
    postSection.hidden = false;
    setUiMode(UI_MODE.POST_CAPTURE);
    setPostCaptureEntryMode("process");
    setCorrelationProgress(false);
    finalResults.hidden = true;
    finalResults.innerHTML = "";
    setCriticalStatus("");
    setStatus("S3 media imported. Continue in Post-capture.");
    renderRawFiles(data.raw_files, data.raw_dir, data.storage_mode, data.storage_target);
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    setS3ImportStatus("S3 session imported successfully.");
    importedS3SessionPrefix = sessionPrefix;
  } catch (err) {
    addLog("error", `S3 media import failed: ${err.message || err}`);
    setS3ImportStatus(err.message || "S3 import failed.", true);
    setStatus(err.message, true);
  } finally {
    importInFlight = false;
    s3ImportInFlight = false;
    processBtn.disabled = false;
    refreshS3SessionsBtn.disabled = false;
    importS3SessionBtn.disabled = false;
  }
}

function resetPanelsForHome() {
  setUiMode(UI_MODE.IDLE);
  homePanel.hidden = false;
  if (captureLocationPanel) captureLocationPanel.hidden = true;
  environmentPanel.hidden = true;
  captureFlowPanel.hidden = true;
  subRegionFlowPanel.hidden = true;
  hideNoReachablePanel();
  hostPanel.hidden = true;
  livePanel.hidden = true;
  postSection.hidden = true;
  stopCaptureConnectivityMonitor();
  stopCaptureReconnectWindow();
  activeCaptureHostIds = [];
}

function updateCaptureLocationDisclaimer() {
  if (!captureLocationDisclaimer) return;
  const mode = captureLocationS3?.checked ? "s3" : "local";
  selectedCaptureStorage = mode;
  if (s3SpoolDirPanel) {
    s3SpoolDirPanel.hidden = mode !== "s3";
  }
  if (mode === "local") {
    captureLocationDisclaimer.textContent = `Files will be saved locally under ${captureRootConfigured || "(configured capture root)"}.`;
    return;
  }
  captureLocationDisclaimer.textContent =
    "AWS S3 upload requires high network throughput. If upload is slower than capture, local disk usage may grow and can fill the disk. If disk space is not enough and internet throughput is low, consider using an external disk.";
}

function resetCaptureLocationSelection() {
  selectedCaptureStorage = "s3";
  selectedS3SpoolDir = "";
  if (captureLocationLocal) captureLocationLocal.checked = false;
  if (captureLocationS3) captureLocationS3.checked = true;
  if (captureLocationS3) {
    captureLocationS3.disabled = !(s3EnabledInApp && s3ConfiguredInApp);
    if (captureLocationS3.disabled) {
      selectedCaptureStorage = "local";
      if (captureLocationLocal) captureLocationLocal.checked = true;
      captureLocationS3.checked = false;
    }
  }
  updateCaptureLocationDisclaimer();
}

async function chooseS3SpoolDirectory() {
  if (!chooseS3SpoolDirBtn) return;
  const currentPath = String(selectedS3SpoolDir || "").trim();
  chooseS3SpoolDirBtn.disabled = true;
  try {
    const payload = currentPath ? { initial_path: currentPath } : {};
    const data = await api("/api/fs/pick-directory", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const selectedPath = String(data.path || "").trim();
    if (!selectedPath) return;
    selectedS3SpoolDir = selectedPath;
    setStatus(`Local tmp directory selected: ${selectedPath}`);
  } catch (err) {
    const msg = String(err?.message || "");
    if (msg.toLowerCase().includes("cancelled")) {
      setStatus("Directory selection cancelled.");
      return;
    }
    setStatus(msg || "Failed to choose directory.", true);
  } finally {
    chooseS3SpoolDirBtn.disabled = false;
  }
}

function showCaptureLocationPanel() {
  homePanel.hidden = true;
  if (captureLocationPanel) captureLocationPanel.hidden = false;
  environmentPanel.hidden = true;
  captureFlowPanel.hidden = true;
  subRegionFlowPanel.hidden = true;
  hostPanel.hidden = true;
  livePanel.hidden = true;
  postSection.hidden = true;
}

function showCaptureScopePanels() {
  homePanel.hidden = true;
  if (captureLocationPanel) captureLocationPanel.hidden = true;
  environmentPanel.hidden = false;
  captureFlowPanel.hidden = true;
  subRegionFlowPanel.hidden = true;
  hostPanel.hidden = true;
  livePanel.hidden = true;
  postSection.hidden = true;
}

function resetUiToInitialState() {
  resetPanelsForHome();
  setCaptureUiRunning(false);

  currentEnvironment = "";
  configuredSubRegionsByRegion = {};
  targetsCache = {};
  lastCapturePreset = null;
  stopCaptureConnectivityMonitor();
  stopCaptureReconnectWindow();
  activeCaptureHostIds = [];

  environmentInput.value = "";
  regionInput.value = "";
  regionInput.innerHTML = '<option value="">Select region...</option>';
  subRegionInput.innerHTML = "";
  subRegionInput.size = 2;
  renderSubRegionChips();
  subRegionInput.disabled = false;
  allSubRegionsToggle.checked = false;
  cleanSubRegionsBtn.disabled = false;

  hostInput.innerHTML = "";
  hostInput.size = 1;
  renderHostChips();
  hostInput.disabled = true;
  allHostsToggle.checked = true;
  cleanSelectionBtn.disabled = false;

  filterInput.value = "";
  outputDirNameInput.value = "";
  if (timeoutMinutesInput) timeoutMinutesInput.value = "";
  mediaDirPicker.value = "";

  sipPcapInput.value = "";
  callDirectionInput.value = "";
  updateCorrelationUiState();

  rawFiles.innerHTML = "";
  setCorrelationProgress(false);
  finalResults.hidden = true;
  finalResults.innerHTML = "";
  counterBox.textContent = "";
  updateCaptureStorageHint("local", "");
  setPostCaptureEntryMode("capture");
  setRegionStatus("");
  setSubRegionStatus("");
  setCriticalStatus("");
  setStatus("Choose an action.");
}

function enterCaptureMode() {
  setUiMode(UI_MODE.IDLE);
  showCaptureLocationPanel();
  stopCaptureConnectivityMonitor();
  stopCaptureReconnectWindow();
  activeCaptureHostIds = [];
  environmentInput.value = "";
  currentEnvironment = "";
  configuredSubRegionsByRegion = {};
  setRegionStatus("");
  setSubRegionStatus("");
  regionInput.value = "";
  regionInput.innerHTML = '<option value="">Select region...</option>';
  subRegionInput.innerHTML = "";
  subRegionInput.size = 2;
  renderSubRegionChips();
  allSubRegionsToggle.checked = false;
  subRegionInput.disabled = false;
  cleanSubRegionsBtn.disabled = false;
  hostInput.innerHTML = "";
  hostInput.size = 1;
  renderHostChips();
  hideNoReachablePanel();
  allHostsToggle.checked = true;
  hostInput.disabled = true;
  cleanSelectionBtn.disabled = false;
  updateCaptureStorageHint("local", "");
  setPostCaptureEntryMode("capture");
  resetCaptureLocationSelection();
  setCriticalStatus("");
  setStatus("Select capture files location to continue.");
}

async function applyCapturePreset(preset) {
  if (!preset || !preset.region) return false;
  if (!preset.environment) return false;

  setUiMode(UI_MODE.IDLE);
  showCaptureScopePanels();
  await loadConfiguredScope(preset.environment);
  if (!configuredSubRegionsByRegion[preset.region]) return false;
  environmentInput.value = preset.environment;
  currentEnvironment = preset.environment;
  regionInput.value = preset.region;
  captureFlowPanel.hidden = false;
  subRegionFlowPanel.hidden = false;
  const reach = await refreshTargets(preset.environment, { forceRefresh: true, region: preset.region });
  if (!reach) return false;
  renderSubRegionSelector(preset.region);
  hideNoReachablePanel();
  hostPanel.hidden = false;

  filterInput.value = preset.filter || "";
  outputDirNameInput.value = preset.outputDirName || "";
  selectedCaptureStorage = String(preset.storageLocation || "local");
  selectedS3SpoolDir = String(preset.s3SpoolDir || "");
  if (timeoutMinutesInput) {
    const timeoutVal = Number(preset.timeoutMinutes);
    timeoutMinutesInput.value = Number.isInteger(timeoutVal) && timeoutVal > 0 ? String(timeoutVal) : "";
  }

  const savedSubRegions = Array.isArray(preset.subRegions) ? preset.subRegions.filter(Boolean) : [];
  if (!preset.allSubRegions && savedSubRegions.length) {
    allSubRegionsToggle.checked = false;
    subRegionInput.disabled = false;
    const selectedSet = new Set(savedSubRegions);
    Array.from(subRegionInput.options).forEach((opt) => {
      opt.selected = selectedSet.has(opt.value);
    });
    renderSubRegionChips();
  } else {
    allSubRegionsToggle.checked = true;
    subRegionInput.disabled = false;
    Array.from(subRegionInput.options).forEach((opt) => {
      opt.selected = true;
    });
    renderSubRegionChips();
  }
  updateHostsFromSubRegionSelection();

  const useAll = Boolean(preset.allHosts);
  allHostsToggle.checked = useAll;
  hostInput.disabled = useAll;
  if (!useAll && Array.isArray(preset.hostIds) && preset.hostIds.length) {
    const selected = new Set(preset.hostIds);
    Array.from(hostInput.options).forEach((opt) => {
      opt.selected = selected.has(opt.value);
    });
  } else {
    Array.from(hostInput.options).forEach((opt) => {
      opt.selected = false;
    });
  }
  renderHostChips();
  return true;
}

function selectedHostIds() {
  if (allHostsToggle?.checked) {
    return [];
  }
  return Array.from(hostInput.selectedOptions)
    .map((opt) => opt.value)
    .filter((v) => v);
}

function parseTimeoutMinutesInput() {
  const raw = String(timeoutMinutesInput?.value || "").trim();
  if (!raw) return null;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error("Timeout (optional) must be a positive integer in minutes");
  }
  return value;
}

function setCaptureUiRunning(running) {
  captureRunning = Boolean(running);
  if (captureRunning) {
    setUiMode(UI_MODE.CAPTURING);
  } else if (uiMode === UI_MODE.CAPTURING) {
    setUiMode(UI_MODE.IDLE);
  }
  if (!captureRunning) {
    leaveStopSent = false;
    closeCaptureLeaveModal();
    lastStorageProgressAt = 0;
  } else if (!lastStorageProgressAt) {
    lastStorageProgressAt = 0;
  }
  updateStartCaptureAvailability();
  stopBtn.disabled = !running;
  cleanBtn.disabled = running;
  environmentInput.disabled = running;
  regionInput.disabled = running;
  subRegionInput.disabled = running;
  allSubRegionsToggle.disabled = running;
  cleanSubRegionsBtn.disabled = running;
  hostInput.disabled = running || Boolean(allHostsToggle?.checked);
  filterInput.disabled = running;
  outputDirNameInput.disabled = running;
  if (timeoutMinutesInput) timeoutMinutesInput.disabled = running;
  allHostsToggle.disabled = running;
  cleanSelectionBtn.disabled = running;
}

function closeCaptureLeaveModal() {
  if (captureLeaveModal) {
    captureLeaveModal.hidden = true;
  }
  pendingLeaveAction = null;
}

function openCaptureLeaveModal(onLeave) {
  pendingLeaveAction = onLeave;
  if (captureLeaveModal) {
    captureLeaveModal.hidden = false;
  }
}

function stopCaptureRuntimeForLeave() {
  stopCaptureConnectivityMonitor();
  stopCaptureReconnectWindow();
  stopReachabilityAutoRetry();
  stopStatusPolling();
}

function stopCaptureOnPageLeave() {
  if (!captureRunning || leaveStopSent || manualStopInProgress) return;
  stopCaptureRuntimeForLeave();
  leaveStopSent = true;
  captureRunning = false;
  try {
    if (navigator && typeof navigator.sendBeacon === "function") {
      const ok = navigator.sendBeacon("/api/capture/stop-safe", new Blob([], { type: "application/octet-stream" }));
      if (ok) return;
    }
  } catch {
    // fallback below
  }
  try {
    fetch("/api/capture/stop-safe", { method: "POST", keepalive: true }).catch(() => {});
  } catch {
    // best effort only
  }
}

function requestId() {
  return Math.random().toString(16).slice(2, 8);
}

async function api(path, options = {}) {
  const rid = requestId();
  const method = (options.method || "GET").toUpperCase();
  const isLogPoll = path === "/api/logs/poll" || path === "/api/logs/stream";

  if (DEBUG_ENABLED && !isLogPoll) {
    if (options.body instanceof FormData) {
      const parts = [];
      for (const [k, v] of options.body.entries()) {
        if (v instanceof File) {
          parts.push(`${k}=${v.name} (${v.size} bytes)`);
        } else {
          parts.push(`${k}=${String(v)}`);
        }
      }
      addLog("debug", `[req ${rid}] ${method} ${path} form: ${parts.join(", ")}`);
    } else if (typeof options.body === "string" && options.body.length < 4000) {
      addLog("debug", `[req ${rid}] ${method} ${path} body: ${options.body}`);
    } else {
      addLog("debug", `[req ${rid}] ${method} ${path}`);
    }
  }

  const response = await fetch(path, options);
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (DEBUG_ENABLED && !isLogPoll) {
    addLog("debug", `[res ${rid}] ${method} ${path} status=${response.status}`);
  }

  if (!response.ok) {
    const detail = data && data.detail;
    let message = "Request failed";
    if (typeof detail === "string" && detail.trim()) {
      message = detail;
    } else if (detail && typeof detail === "object") {
      if (typeof detail.message === "string" && detail.message.trim()) {
        message = detail.message;
      } else if (typeof detail.detail === "string" && detail.detail.trim()) {
        message = detail.detail;
      }
    }
    const err = new Error(message);
    if (detail && typeof detail === "object") {
      if (Array.isArray(detail.log_tail)) {
        err.log_tail = detail.log_tail;
      }
      err.server_detail = detail;
    }
    throw err;
  }
  return data;
}

function toLogicalRegion(subRegionName) {
  const n = String(subRegionName || "").toLowerCase();
  if (n.startsWith("eu")) return "EU";
  if (n.startsWith("us")) return "US";
  return (subRegionName || "").toUpperCase();
}

function parseTargetsByRegion(raw) {
  const logical = {};
  Object.entries(raw || {}).forEach(([regionKey, value]) => {
    if (!logical[regionKey]) {
      logical[regionKey] = { subregions: {} };
    }
    if (value && !Array.isArray(value) && typeof value === "object") {
      Object.entries(value).forEach(([subRegion, hosts]) => {
        logical[regionKey].subregions[subRegion] = (Array.isArray(hosts) ? hosts : []).map((h) => ({
          ...h,
          sub_region: subRegion,
        }));
      });
      return;
    }
    const logicalRegion = toLogicalRegion(regionKey);
    if (!logical[logicalRegion]) {
      logical[logicalRegion] = { subregions: {} };
    }
    logical[logicalRegion].subregions[regionKey] = (Array.isArray(value) ? value : []).map((h) => ({
      ...h,
      sub_region: regionKey,
    }));
  });
  return logical;
}

function populateRegionSelector() {
  const regions = Object.keys(configuredSubRegionsByRegion || {}).sort();
  regionInput.innerHTML = '<option value="">Select region...</option>';
  regions.forEach((region) => {
    const opt = document.createElement("option");
    opt.value = region;
    opt.textContent = region;
    regionInput.appendChild(opt);
  });
}

function populateEnvironmentSelector(environments, selected = "") {
  const values = Array.isArray(environments) ? environments.slice() : [];
  const current = environmentInput.value;
  environmentInput.innerHTML = '<option value="">Select environment...</option>';
  values.forEach((env) => {
    const opt = document.createElement("option");
    opt.value = env;
    opt.textContent = env;
    environmentInput.appendChild(opt);
  });
  const preferred = selected || current || values[0] || "";
  if (preferred) {
    environmentInput.value = preferred;
  }
}

function hostsForRegionAndSubregions(region, selectedSubRegions) {
  const regionData = targetsCache[region] || { subregions: {} };
  const subregions = regionData.subregions || {};
  const selected = Array.isArray(selectedSubRegions) ? selectedSubRegions.filter(Boolean) : [];
  if (!selected.length) {
    return [];
  }
  return selected.flatMap((sr) => (subregions[sr] || []).slice());
}

function renderSubRegionSelector(region) {
  const values = Array.isArray(configuredSubRegionsByRegion[region]) ? configuredSubRegionsByRegion[region].slice().sort() : [];
  if (!values.length) {
    subRegionFlowPanel.hidden = true;
    subRegionInput.innerHTML = "";
    subRegionInput.size = 2;
    renderSubRegionChips();
    return;
  }

  subRegionFlowPanel.hidden = false;
  subRegionInput.innerHTML = "";

  values.forEach((sr) => {
    const opt = document.createElement("option");
    opt.value = sr;
    opt.textContent = sr;
    subRegionInput.appendChild(opt);
  });
  subRegionInput.size = fitListSize(values.length);
  allSubRegionsToggle.checked = true;
  subRegionInput.disabled = false;
  Array.from(subRegionInput.options).forEach((opt) => {
    opt.selected = true;
  });
  renderSubRegionChips();
}

function getSelectedSubRegions() {
  if (allSubRegionsToggle.checked) {
    return Array.from(subRegionInput.options).map((opt) => opt.value).filter(Boolean);
  }
  return Array.from(subRegionInput.selectedOptions).map((opt) => opt.value).filter(Boolean);
}

function renderHosts(region, subRegions) {
  hostInput.innerHTML = "";
  hostInput.size = 1;
  const hosts = hostsForRegionAndSubregions(region, subRegions);

  if (!hosts.length) {
    hostInput.size = 1;
    renderHostChips();
    startBtn.disabled = true;
    return false;
  }

  hosts.forEach((h) => {
    const opt = document.createElement("option");
    opt.value = h.id;
    const parts = [h.id];
    if (h.description) parts.push(h.description);
    opt.textContent = parts.join(" - ");
    hostInput.appendChild(opt);
  });
  hostInput.size = fitListSize(hosts.length);
  renderHostChips();

  startBtn.disabled = false;
  setStatus(`Reachable hosts: ${hosts.length}. Ready to start capture.`);
  return true;
}

function updateHostsFromSubRegionSelection(options = {}) {
  const autoRetry = Boolean(options.autoRetry);
  const region = regionInput.value;
  if (!region) {
    hideNoReachablePanel();
    hostPanel.hidden = true;
    startBtn.disabled = true;
    return;
  }
  const selected = getSelectedSubRegions();
  if (!selected.length) {
    hideNoReachablePanel();
    hostPanel.hidden = true;
    startBtn.disabled = true;
    setSubRegionStatus("");
    setStatus("Select one or more sub-regions to continue.");
    return;
  }
  if (reachabilityRetryInFlight) return;
  reachabilityRetryInFlight = true;
  const requestSeq = ++hostSelectionRequestSeq;
  hostPanel.hidden = true;
  const label = selected.join(", ");
  setSubRegionStatus(`Testing RTPEngine reachability in ${label}`);
  if (!autoRetry) {
    setStatus(`Testing RTPEngine reachability in ${label}`);
  }
  refreshTargets(environmentInput.value, { forceRefresh: true, region })
    .then((data) => {
      if (requestSeq !== hostSelectionRequestSeq) return;
      if (!data) return;
      setSubRegionStatus("");
      const hasHosts = renderHosts(region, selected);
      if (!hasHosts) {
        hostPanel.hidden = true;
        showNoReachablePanel(region);
        setStatus(`No reachable hosts found for ${currentEnvironment}/${region}.`, true);
        return;
      }
      hideNoReachablePanel();
      hostPanel.hidden = false;
      allHostsToggle.checked = true;
      hostInput.disabled = true;
      cleanSelectionBtn.disabled = false;
    })
    .catch((err) => {
      if (requestSeq !== hostSelectionRequestSeq) return;
      if (err?.name === "AbortError") return;
      showNoReachablePanel(region);
      setSubRegionStatus(err.message || "Failed to load reachable hosts.", true);
      setStatus(err.message || "Failed to load reachable hosts.", true);
      addLog("error", `Failed reachability check for hosts ${environmentInput.value}/${region}: ${err.message || "unknown error"}`);
    })
    .finally(() => {
      reachabilityRetryInFlight = false;
    });
}

async function refreshTargets(environment = "", options = {}) {
  const forceRefresh = Boolean(options.forceRefresh);
  const selectedRegion = String(options.region || "").trim();
  const requestSeq = ++targetsRequestSeq;
  if (targetsAbortController) {
    targetsAbortController.abort();
  }
  targetsAbortController = new AbortController();
  const env = String(environment || environmentInput.value || currentEnvironment || "QA").toUpperCase();
  setStatus("Checking rpcap reachability for selected region...");
  if (forceRefresh) {
    addLog("info", "Checking reachability (rpcapd)...");
  }
  const qs = new URLSearchParams({ environment: env });
  if (selectedRegion) {
    qs.set("region", selectedRegion);
  }
  if (forceRefresh) {
    qs.set("refresh", "true");
  }
  let data = null;
  try {
    data = await api(`/api/targets?${qs.toString()}`, { signal: targetsAbortController.signal });
  } catch (err) {
    if (err?.name === "AbortError") {
      return null;
    }
    throw err;
  }
  if (requestSeq !== targetsRequestSeq) {
    return null;
  }
  currentEnvironment = String(data.selected_environment || env || "QA").toUpperCase();
  targetsCache = parseTargetsByRegion(data.reachable || {});
  const regionCount = Object.keys(targetsCache).length;
  addLog("info", `Reachable regions=${regionCount} (${Object.keys(targetsCache).join(", ") || "-"}) environment=${currentEnvironment}`);
  if (selectedRegion && !targetsCache[selectedRegion]) {
    setStatus(`No reachable hosts found for ${currentEnvironment}/${selectedRegion}.`, true);
  }
  return data;
}

async function loadConfiguredScope(environment = "") {
  const env = String(environment || environmentInput.value || currentEnvironment || "QA").toUpperCase();
  const data = await api(`/api/config/scope?environment=${encodeURIComponent(env)}`);
  currentEnvironment = String(data.selected_environment || env || "QA").toUpperCase();
  targetsCache = {};
  populateEnvironmentSelector(data.configured_environments || [], currentEnvironment);
  configuredSubRegionsByRegion = data.configured_sub_regions || {};
  populateRegionSelector();
  return data;
}

function updateCaptureStorageHint(storageMode, storageTarget) {
  if (!captureStorageHint) return;
  const mode = String(storageMode || "").toLowerCase();
  const target = String(storageTarget || "").trim();
  if (mode === "s3" && target) {
    captureStorageHint.textContent = `Files are stored in S3 under ${target}`;
    return;
  }
  if (target) {
    captureStorageHint.textContent = `Files are stored under ${target}/...`;
    return;
  }
  captureStorageHint.textContent = "Files are stored under captures/<name>/<timestamp>/...";
}

function renderRawFiles(rawFileMap, rawDir, storageMode = "", storageTarget = "") {
  const mapObj = rawFileMap || {};
  const totalLinks = Object.values(mapObj).reduce(
    (acc, links) => acc + (Array.isArray(links) ? links.length : 0),
    0
  );
  hasLoadedMediaForCorrelation = totalLinks > 0;
  const where = String(storageTarget || rawDir || "");
  const label = String(storageMode || "").toLowerCase() === "s3" ? "S3 capture files are stored in:" : "Raw capture files are stored in:";
  let html = `<p>${label} <code>${where}</code></p>`;
  html += '<div class="raw-files-grid">';
  Object.entries(mapObj).forEach(([host, links]) => {
    html += '<section class="raw-host-card">';
    html += `<h4>${host}</h4>`;
    if (!links.length) {
      html += "<p>No files generated.</p>";
      html += "</section>";
      return;
    }
    html += "<ul>";
    links.forEach((link) => {
      const value = String(link || "");
      const downloadable = value.startsWith("/") || /^https?:\/\//i.test(value);
      if (downloadable) {
        html += `<li><a href="${value}" target="_blank">${value.split("/").pop()}</a></li>`;
      } else {
        html += `<li><code>${value}</code></li>`;
      }
    });
    html += "</ul>";
    html += "</section>";
  });
  html += "</div>";
  rawFiles.innerHTML = html;
  updateCorrelationUiState();
}

async function refreshRawFilesFromLatestSession() {
  try {
    const data = await api("/api/files/latest");
    const rawMap = data.raw || data.raw_files || {};
    const rawDir = data.raw_dir || data.storage_target || "";
    const mode = data.storage_mode || "";
    const target = data.storage_target || "";
    renderRawFiles(rawMap, rawDir, mode, target);
  } catch (err) {
    addLog("warn", `Could not refresh final media files: ${err.message || err}`);
  }
}

function stopStatusPolling() {
  if (statusTimer) {
    clearTimeout(statusTimer);
    statusTimer = null;
  }
}

function scheduleStatusPolling(delayMs = STATUS_POLLING_BASE_MS) {
  stopStatusPolling();
  statusTimer = setTimeout(runStatusPollingTick, Math.max(500, Number(delayMs) || STATUS_POLLING_BASE_MS));
}

async function runStatusPollingTick() {
  try {
    const data = await api("/api/capture/status");
    if (statusPollingFailures > 0) {
      addLog("info", "Capture status polling recovered.");
    }
    statusPollingFailures = 0;
    statusPollingBackoffMs = STATUS_POLLING_BASE_MS;
    statusPollingLastWarnAt = 0;
    if (!data.session_id) {
      scheduleStatusPolling();
      return;
    }

    const counts = data.packet_counts || {};
    const hostCounts = Object.entries(counts)
      .filter(([host]) => host !== "total")
      .map(([host, value]) => `${host}: ${value}`)
      .join(" | ");
    setLiveMetricsThrottled(`Total packets: ${counts.total || 0}${hostCounts ? ` (${hostCounts})` : ""}`);
    updateHostConnectivityState(counts);

    if (data.failed) {
      const reason = data.failure_reason || "Unknown error";
      if (captureRecovering || captureAutoRestartInProgress) {
        setStatus("Attempting to re-establish capture...");
        scheduleStatusPolling();
        return;
      }
      setStatus(`Capture stopped due to an error: ${reason}`, true);
      setCriticalStatus(`Capture stopped due to an error: ${reason}`, true);
      scheduleStatusPolling();
      return;
    }
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    applyStorageFlushState(data.storage_flush);

    if (!data.running) {
      const flushActive = isStorageFlushActive(data.storage_flush);
      if (!flushActive) {
        stopStatusPolling();
      }
      const shouldTransitionToPost = captureRunning && data.session_id && data.session_id !== lastAutoStopSessionId;
      setCaptureUiRunning(false);
      stopCaptureConnectivityMonitor();
      stopCaptureReconnectWindow();
      resetHostConnectivityState();
      activeCaptureHostIds = [];
      if (shouldTransitionToPost) {
        lastAutoStopSessionId = data.session_id;
        environmentPanel.hidden = true;
        captureFlowPanel.hidden = true;
        subRegionFlowPanel.hidden = true;
        hideNoReachablePanel();
        hostPanel.hidden = true;
        livePanel.hidden = true;
        postSection.hidden = false;
        setUiMode(UI_MODE.POST_CAPTURE);
        setPostCaptureEntryMode("capture");
        renderRawFiles(data.raw_files, data.raw_dir, data.storage_mode, data.storage_target);
        applyStorageFlushState(data.storage_flush);
        if (String(data.stop_reason || "").toLowerCase() === "timeout") {
          const timeoutValue = Number(data.timeout_minutes);
          const timeoutLabel = Number.isInteger(timeoutValue) && timeoutValue > 0
            ? `${timeoutValue} minute(s)`
            : "configured timeout";
          addLog("warn", `Capture stopped automatically: timeout reached (${timeoutLabel}) session_id=${data.session_id}`);
          addLog("info", `Capture stopped session_id=${data.session_id}`);
          setStatus("Capture stopped.");
        } else {
          setStatus("Capture stopped.");
        }
      } else if (String(data.stop_reason || "").toLowerCase() === "timeout") {
        const timeoutValue = Number(data.timeout_minutes);
        const timeoutLabel = Number.isInteger(timeoutValue) && timeoutValue > 0
          ? `${timeoutValue} minute(s)`
          : "configured timeout";
        addLog("warn", `Capture stopped automatically: timeout reached (${timeoutLabel}) session_id=${data.session_id}`);
        setStatus("Capture stopped.");
      } else {
        setStatus("Capture stopped.");
      }
      setCriticalStatus("");
      if (flushActive) {
        scheduleStatusPolling(2000);
      }
      return;
    }
  } catch (err) {
    statusPollingFailures += 1;
    statusPollingBackoffMs = Math.min(STATUS_POLLING_MAX_MS, STATUS_POLLING_BASE_MS * (2 ** (statusPollingFailures - 1)));
    const now = Date.now();
    if (
      statusPollingFailures <= 2 ||
      (now - statusPollingLastWarnAt) >= LOG_POLL_WARN_INTERVAL_MS
    ) {
      addLog(
        "warn",
        `Capture status polling delayed failures=${statusPollingFailures} next_retry_ms=${statusPollingBackoffMs}`
      );
      statusPollingLastWarnAt = now;
    }
  } finally {
    if (captureRunning || captureRecovering || captureAutoRestartInProgress) {
      scheduleStatusPolling(statusPollingBackoffMs);
    }
  }
}

function startStatusPolling() {
  statusPollingFailures = 0;
  statusPollingBackoffMs = STATUS_POLLING_BASE_MS;
  lastLiveMetricsUpdateAt = 0;
  scheduleStatusPolling(200);
}

function updateCorrelationUiState() {
  const hasSip = Boolean(sipPcapInput?.files && sipPcapInput.files.length);
  const validDirection = ["inbound", "outbound"].includes((callDirectionInput?.value || "").toLowerCase());
  correlateBtn.disabled = !hasSip || !validDirection || !hasLoadedMediaForCorrelation || correlateInFlight || s3UploadGateActive;
  if (cancelCorrelationBtn) {
    cancelCorrelationBtn.disabled = !correlateInFlight;
  }
}

function renderFinalFiles(files) {
  const enc = files.encrypted_media;
  const dec = files.decrypted_media;
  const sip = files.sip_plus_decrypted_media;

  let html = "<h3>Downloads</h3><ul>";
  if (enc) html += `<li><a href="${enc}" target="_blank">media_raw.pcap</a></li>`;
  if (dec) html += `<li><a href="${dec}" target="_blank">media_decrypted.pcap</a></li>`;
  if (sip) html += `<li><a href="${sip}" target="_blank">SIP_plus_media_decrypted.pcap</a></li>`;
  html += "</ul>";
  finalResults.innerHTML = html;
  finalResults.hidden = false;
}

function renderCorrelationNotice(message, level = "warn") {
  const safe = escapeHtml(message || "No downloadable outputs were produced.");
  const cls = level === "error" ? "correlation-notice error" : "correlation-notice warn";
  finalResults.innerHTML = `<div class="${cls}">${safe}</div>`;
  finalResults.hidden = false;
}

showLogsToggle.addEventListener("click", () => {
  setLogsVisible(logSection.hidden);
});

captureLocationLocal?.addEventListener("change", () => {
  updateCaptureLocationDisclaimer();
});

captureLocationS3?.addEventListener("change", () => {
  updateCaptureLocationDisclaimer();
});

captureLocationBackBtn?.addEventListener("click", () => {
  resetPanelsForHome();
  setStatus("Choose an action.");
});

captureLocationContinueBtn?.addEventListener("click", () => {
  const wantsS3 = Boolean(captureLocationS3?.checked);
  if (wantsS3 && !(s3EnabledInApp && s3ConfiguredInApp)) {
    setStatus("AWS S3 option is not available with current configuration.", true);
    return;
  }
  selectedCaptureStorage = wantsS3 ? "s3" : "local";
  selectedS3SpoolDir = wantsS3 ? String(selectedS3SpoolDir || "").trim() : "";
  showCaptureScopePanels();
  setStatus("Select an environment to continue.");
});

chooseS3SpoolDirBtn?.addEventListener("click", () => {
  chooseS3SpoolDirectory();
});

captureModeBtn.addEventListener("click", async () => {
  if (captureRunning) {
    openCaptureLeaveModal(() => {
      enterCaptureMode();
    });
    return;
  }
  enterCaptureMode();
});

processBtn.addEventListener("click", () => {
  if (captureRunning) {
    openCaptureLeaveModal(() => {
      if (importInFlight) return;
      postSection.hidden = false;
      setUiMode(UI_MODE.POST_CAPTURE);
      setPostCaptureEntryMode("process");
      hasLoadedMediaForCorrelation = false;
      setS3UploadGate(false, 0);
      rawFiles.innerHTML = "";
      updateCorrelationUiState();
      refreshS3Sessions(false);
      if (s3ImportPanel) s3ImportPanel.hidden = true;
      setMediaSourceStatus("Choose media source: local directory or S3 session.");
      setStatus("Choose media source before importing files.");
    });
    return;
  }
  if (importInFlight) return;
  postSection.hidden = false;
  setUiMode(UI_MODE.POST_CAPTURE);
  setPostCaptureEntryMode("process");
  hasLoadedMediaForCorrelation = false;
  setS3UploadGate(false, 0);
  rawFiles.innerHTML = "";
  updateCorrelationUiState();
  refreshS3Sessions(false);
  if (s3ImportPanel) s3ImportPanel.hidden = true;
  setMediaSourceStatus("Choose media source: local directory or S3 session.");
  setStatus("Choose media source before importing files.");
});

retryReachabilityBtn?.addEventListener("click", () => {
  if (captureLossUiMode) {
    if (captureConnectivityCheckInFlight) return;
    captureConnectivityCheckInFlight = true;
    isCaptureConnectivityHealthy()
      .then(async (healthy) => {
        if (!healthy) {
          setStatus("Connectivity still unavailable.", true);
          return;
        }
        stopCaptureReconnectWindow();
        await restartCaptureFromPresetAfterRecovery();
        startCaptureConnectivityMonitor();
      })
      .catch((err) => {
        addLog("warn", `Manual connectivity retry failed: ${err.message || err}`);
      })
      .finally(() => {
        captureConnectivityCheckInFlight = false;
      });
    return;
  }
  updateHostsFromSubRegionSelection();
});

refreshS3SessionsBtn?.addEventListener("click", () => {
  refreshS3Sessions();
});

importS3SessionBtn?.addEventListener("click", () => {
  importSelectedS3Session();
});

s3SessionSelect?.addEventListener("change", () => {
  if (importInFlight || s3ImportInFlight) return;
  const sessionPrefix = String(s3SessionSelect.value || "").trim();
  if (!sessionPrefix) {
    setS3ImportStatus("Select an S3 session.");
    importedS3SessionPrefix = "";
    return;
  }
  if (sessionPrefix === importedS3SessionPrefix && hasLoadedMediaForCorrelation) {
    setS3ImportStatus("S3 session already selected.");
    return;
  }
  importSelectedS3Session();
});

environmentInput.addEventListener("change", async () => {
  const env = String(environmentInput.value || "").toUpperCase();
  if (!env) {
    regionInput.innerHTML = '<option value="">Select region...</option>';
    configuredSubRegionsByRegion = {};
    captureFlowPanel.hidden = true;
    subRegionFlowPanel.hidden = true;
    hideNoReachablePanel();
    hostPanel.hidden = true;
    livePanel.hidden = true;
    postSection.hidden = true;
    setStatus("Select an environment to continue.");
    setSubRegionStatus("");
    return;
  }
  try {
    await loadConfiguredScope(env);
    captureFlowPanel.hidden = false;
    setRegionStatus("");
    setSubRegionStatus("");
    regionInput.value = "";
    subRegionInput.innerHTML = "";
    subRegionInput.size = 2;
    renderSubRegionChips();
    allSubRegionsToggle.checked = false;
    subRegionInput.disabled = false;
    hostInput.innerHTML = "";
    hostInput.size = 1;
    renderHostChips();
    subRegionFlowPanel.hidden = true;
    hideNoReachablePanel();
    hostPanel.hidden = true;
    livePanel.hidden = true;
    postSection.hidden = true;
    startBtn.disabled = true;
    allHostsToggle.checked = true;
    hostInput.disabled = true;
    setStatus(`Environment ${env} selected. Choose a region.`);
  } catch (err) {
    setStatus(err.message || "Failed to load targets for selected environment.", true);
    addLog("error", `Failed to load environment ${env}: ${err.message || "unknown error"}`);
  }
});

regionInput.addEventListener("change", () => {
  if (!environmentInput.value) {
    setStatus("Select an environment first.", true);
    return;
  }
  const region = regionInput.value;
  if (!region) {
    setRegionStatus("");
    setSubRegionStatus("");
    subRegionFlowPanel.hidden = true;
    hideNoReachablePanel();
    hostPanel.hidden = true;
    livePanel.hidden = true;
    return;
  }

  subRegionFlowPanel.hidden = false;
  hideNoReachablePanel();
  hostPanel.hidden = true;
  livePanel.hidden = true;
  postSection.hidden = true;
  setRegionStatus("");
  setSubRegionStatus("");
  renderSubRegionSelector(region);
  if (subRegionInput.options.length) {
    updateHostsFromSubRegionSelection();
  }
});

subRegionInput.addEventListener("change", () => {
  const total = subRegionInput.options.length;
  const selected = subRegionInput.selectedOptions.length;
  allSubRegionsToggle.checked = total > 0 && selected === total;
  updateHostsFromSubRegionSelection();
});

allSubRegionsToggle.addEventListener("change", () => {
  const checked = Boolean(allSubRegionsToggle.checked);
  if (checked) {
    Array.from(subRegionInput.options).forEach((opt) => {
      opt.selected = true;
    });
  } else {
    Array.from(subRegionInput.options).forEach((opt) => {
      opt.selected = false;
    });
  }
  renderSubRegionChips();
  updateHostsFromSubRegionSelection();
});

cleanSubRegionsBtn.addEventListener("click", () => {
  allSubRegionsToggle.checked = false;
  subRegionInput.disabled = false;
  Array.from(subRegionInput.options).forEach((opt) => {
    opt.selected = false;
  });
  renderSubRegionChips();
  updateHostsFromSubRegionSelection();
});

subRegionInput.addEventListener("mousedown", (ev) => {
  if (!(ev.target instanceof HTMLOptionElement) || subRegionInput.disabled) {
    return;
  }
  ev.preventDefault();
  ev.target.selected = !ev.target.selected;
  const total = subRegionInput.options.length;
  const selected = subRegionInput.selectedOptions.length;
  allSubRegionsToggle.checked = total > 0 && selected === total;
  updateHostsFromSubRegionSelection();
});

allHostsToggle.addEventListener("change", () => {
  const checked = Boolean(allHostsToggle.checked);
  hostInput.disabled = checked;
  if (checked) {
    Array.from(hostInput.options).forEach((opt) => {
      opt.selected = false;
    });
  }
  renderHostChips();
});

cleanSelectionBtn.addEventListener("click", () => {
  Array.from(hostInput.options).forEach((opt) => {
    opt.selected = false;
  });
  allHostsToggle.checked = false;
  hostInput.disabled = false;
  renderHostChips();
});

cleanBtn.addEventListener("click", () => {
  if (cleanBtn.disabled) return;
  environmentInput.value = "";
  currentEnvironment = "";
  configuredSubRegionsByRegion = {};
  setRegionStatus("");
  setSubRegionStatus("");
  regionInput.value = "";
  regionInput.innerHTML = '<option value="">Select region...</option>';
  environmentPanel.hidden = false;
  captureFlowPanel.hidden = true;
  subRegionInput.innerHTML = "";
  subRegionInput.size = 2;
  renderSubRegionChips();
  allSubRegionsToggle.checked = false;
  subRegionInput.disabled = false;
  cleanSubRegionsBtn.disabled = false;
  subRegionFlowPanel.hidden = true;
  hostInput.innerHTML = "";
  renderHostChips();
  hostPanel.hidden = true;
  livePanel.hidden = true;
  postSection.hidden = true;
  filterInput.value = "";
  outputDirNameInput.value = "";
  if (timeoutMinutesInput) timeoutMinutesInput.value = "";
  allHostsToggle.checked = true;
  hostInput.disabled = true;
  cleanSelectionBtn.disabled = false;
  setStatus("Filters cleared. Select an environment to restart.");
});

homepageBtn.addEventListener("click", () => {
  if (captureRunning) {
    openCaptureLeaveModal(() => {
      resetUiToInitialState();
    });
    return;
  }
  resetUiToInitialState();
});

restartCaptureBtn.addEventListener("click", () => {
  if (postCaptureEntryMode === "process") {
    enterCaptureMode();
    setStatus("Select capture files location to continue.");
    return;
  }
  if (!lastCapturePreset) {
    enterCaptureMode();
    setStatus("No previous capture filters found. Select capture files location to start a new capture.");
    return;
  }
  applyCapturePreset(lastCapturePreset)
    .then((ok) => {
      if (!ok) {
        setStatus("Previous capture filters are not available in current configuration.", true);
        return;
      }
      setStatus("Previous capture filters restored. Click Start Capture to restart.");
    })
    .catch((err) => {
      setStatus(err.message || "Failed to restore previous capture filters.", true);
    });
});

startBtn.addEventListener("click", async () => {
  if (captureRecovering || captureAutoRestartInProgress) {
    setStatus("Attempting to re-establish capture...");
    return;
  }
  startBtn.disabled = true;
  try {
    const selectedEnvironment = String(environmentInput.value || "").toUpperCase();
    if (!selectedEnvironment) {
      throw new Error("Please select an environment before starting capture");
    }
    const selectedRegion = String(regionInput.value || "").trim();
    if (!selectedRegion) {
      throw new Error("Please select a valid region before starting capture");
    }
    const selectedSubRegions = getSelectedSubRegions();
    if (!selectedSubRegions.length) {
      throw new Error("Please select one or more sub-regions before starting capture");
    }
    const hostIds = selectedHostIds();
    const timeoutMinutes = parseTimeoutMinutesInput();
    const payload = {
      environment: selectedEnvironment,
      region: selectedRegion,
      sub_regions: selectedSubRegions,
      host_ids: hostIds,
      filter: filterInput.value,
      output_dir_name: outputDirNameInput.value || "",
      storage_location: selectedCaptureStorage,
      s3_spool_dir: selectedCaptureStorage === "s3" ? String(selectedS3SpoolDir || "").trim() : "",
      timeout_minutes: timeoutMinutes,
    };
    lastCapturePreset = {
      environment: selectedEnvironment,
      region: selectedRegion,
      subRegions: selectedSubRegions.slice(),
      hostIds: hostIds.slice(),
      allSubRegions: Boolean(allSubRegionsToggle.checked),
      allHosts: Boolean(allHostsToggle.checked),
      filter: filterInput.value || "",
      outputDirName: outputDirNameInput.value || "",
      storageLocation: selectedCaptureStorage,
      s3SpoolDir: selectedCaptureStorage === "s3" ? String(selectedS3SpoolDir || "").trim() : "",
      timeoutMinutes: timeoutMinutes,
      sessionId: "",
    };
    addLog(
      "info",
      `Starting capture: environment=${payload.environment} region=${payload.region} sub-regions=${payload.sub_regions.join(",")} hosts=${hostIds.length ? hostIds.join(",") : "(all)"} filter=${payload.filter || "(default udp)"}`
    );
    const data = await api("/api/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    setCriticalStatus(`Active capture running in ${data.environment}/${data.region}. Leaving this page will cancel the capture.`, false);
    setStatus("Capture started.");
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    addLog("info", `Capture started session_id=${data.session_id}`);
    if (lastCapturePreset) {
      lastCapturePreset.sessionId = data.session_id;
    }
    lastAutoStopSessionId = data.session_id || "";
    activeCaptureHostIds = Array.isArray(data.hosts) ? data.hosts.slice() : [];
    resetHostConnectivityState();
    lastStorageFlushState = "";
    stopCaptureReconnectWindow();
    setCaptureUiRunning(true);
    livePanel.hidden = false;
    postSection.hidden = true;
    setCorrelationProgress(false);
    finalResults.hidden = true;
    finalResults.innerHTML = "";
    startStatusPolling();
  } catch (err) {
    setStatus(err.message, true);
    addLog("error", `Start capture failed: ${err.message}`);
    setCaptureUiRunning(false);
    stopCaptureConnectivityMonitor();
    resetHostConnectivityState();
  }
});

stopBtn.addEventListener("click", async () => {
  if (manualStopInProgress) return;
  manualStopInProgress = true;
  try {
    stopCaptureConnectivityMonitor();
    setStatus("Stopping capture. Please wait...");
    addLog("info", "Stopping capture...");
    const data = await api("/api/capture/stop", { method: "POST" });
    stopCaptureConnectivityMonitor();
    stopCaptureReconnectWindow();
    resetHostConnectivityState();
    activeCaptureHostIds = [];
    setCaptureUiRunning(false);
    setCriticalStatus("");
    setStatus("Capture stopped.");
    addLog("info", `Capture stopped session_id=${data.session_id}`);
    if (lastCapturePreset) {
      lastCapturePreset.sessionId = data.session_id;
    }
    environmentPanel.hidden = true;
    captureFlowPanel.hidden = true;
    subRegionFlowPanel.hidden = true;
    hideNoReachablePanel();
    hostPanel.hidden = true;
    livePanel.hidden = true;
    postSection.hidden = false;
    setUiMode(UI_MODE.POST_CAPTURE);
    setPostCaptureEntryMode("capture");
    renderRawFiles(data.raw_files, data.raw_dir, data.storage_mode, data.storage_target);
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    applyStorageFlushState(data.storage_flush);
    refreshS3Sessions(false);
    if (isStorageFlushActive(data.storage_flush)) {
      startStatusPolling();
    }
  } catch (err) {
    setStatus(err.message, true);
    addLog("error", `Stop capture failed: ${err.message}`);
  } finally {
    manualStopInProgress = false;
  }
});

async function importLocalMediaByReference() {
  if (importInFlight) return;
  try {
    importInFlight = true;
    processBtn.disabled = true;
    const picked = await api("/api/fs/pick-directory", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const payload = {
      output_dir_name: "",
      directory: String(picked.path || ""),
    };
    addLog("info", `Selected local media directory=${payload.directory}`);
    const data = await api("/api/capture/import-local", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    addLog("info", `Media reference import completed session_id=${data.session_id}`);

    homePanel.hidden = true;
    environmentPanel.hidden = true;
    captureFlowPanel.hidden = true;
    subRegionFlowPanel.hidden = true;
    hideNoReachablePanel();
    hostPanel.hidden = true;
    livePanel.hidden = true;
    postSection.hidden = false;
    setUiMode(UI_MODE.POST_CAPTURE);
    setPostCaptureEntryMode("process");
    setCorrelationProgress(false);
    finalResults.hidden = true;
    finalResults.innerHTML = "";

    setCriticalStatus("");
    setStatus("Local media loaded by reference. Continue in Post-capture.");
    renderRawFiles(data.raw_files, data.raw_dir, data.storage_mode, data.storage_target);
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    refreshS3Sessions();
  } catch (err) {
    const msg = String(err?.message || "");
    if (msg.toLowerCase().includes("cancelled")) {
      setStatus("Media selection cancelled.");
      return;
    }
    addLog("error", `Media import failed: ${msg}`);
    setStatus(msg, true);
  } finally {
    importInFlight = false;
    processBtn.disabled = false;
  }
}

chooseLocalMediaBtn?.addEventListener("click", () => {
  if (importInFlight || s3ImportInFlight) return;
  if (s3ImportPanel) s3ImportPanel.hidden = true;
  setMediaSourceStatus("Local source selected. Choose a folder with media files.");
  importLocalMediaByReference();
});

showS3MediaBtn?.addEventListener("click", async () => {
  if (importInFlight || s3ImportInFlight) return;
  if (s3ImportPanel) s3ImportPanel.hidden = false;
  setMediaSourceStatus("S3 source selected. Choose a session to import automatically.");
  await refreshS3Sessions();
});

async function syncUiWithServerCaptureState() {
  const data = await api("/api/capture/status");
  if (!data.session_id) {
    setCaptureUiRunning(false);
    stopCaptureConnectivityMonitor();
    return;
  }

  if (data.running) {
    homePanel.hidden = true;
    environmentPanel.hidden = false;
    captureFlowPanel.hidden = false;
    subRegionFlowPanel.hidden = false;
    hideNoReachablePanel();
    hostPanel.hidden = false;
    livePanel.hidden = false;
    postSection.hidden = true;

    if (data.environment) {
      await loadConfiguredScope(String(data.environment).toUpperCase());
      environmentInput.value = String(data.environment).toUpperCase();
    }
    if (data.region) {
      regionInput.value = data.region;
      await refreshTargets(String(data.environment || environmentInput.value || "").toUpperCase(), { forceRefresh: true, region: data.region });
      renderSubRegionSelector(data.region);
      const runningSubRegions = Array.isArray(data.sub_regions) ? data.sub_regions.filter(Boolean) : [];
      if (runningSubRegions.length) {
        const allCount = subRegionInput.options.length;
        allSubRegionsToggle.checked = runningSubRegions.length >= allCount && allCount > 0;
        subRegionInput.disabled = false;
        const selectedSet = new Set(runningSubRegions);
        Array.from(subRegionInput.options).forEach((opt) => {
          opt.selected = selectedSet.has(opt.value);
        });
      }
      updateHostsFromSubRegionSelection();
    }
    if (timeoutMinutesInput) {
      const timeoutVal = Number(data.timeout_minutes);
      timeoutMinutesInput.value = Number.isInteger(timeoutVal) && timeoutVal > 0 ? String(timeoutVal) : "";
    }
    setCaptureUiRunning(true);
    activeCaptureHostIds = Object.keys((data.packet_counts || {})).filter((k) => k !== "total");
    resetHostConnectivityState();
    setCriticalStatus(`Active capture running in ${data.environment}/${data.region}. Leaving this page will cancel the capture.`, false);
    setStatus("Capture resumed.");
    handleStorageState(data.storage_mode, data.storage_notice, data.storage_target);
    addLog("warn", `Capture already running session_id=${data.session_id} environment=${data.environment} region=${data.region}`);
    if (lastCapturePreset) {
      lastCapturePreset.sessionId = data.session_id;
      lastCapturePreset.timeoutMinutes = Number(data.timeout_minutes) || null;
    }
    startStatusPolling();
  } else {
    setCaptureUiRunning(false);
    stopCaptureConnectivityMonitor();
    resetHostConnectivityState();
  }
}

correlateBtn.addEventListener("click", async () => {
  if (correlateInFlight) return;
  if (!sipPcapInput.files.length) {
    addLog("error", "Please upload a SIP pcap file.");
    return;
  }
  if (!["inbound", "outbound"].includes((callDirectionInput.value || "").toLowerCase())) {
    addLog("error", "Please select call direction (Inbound or Outbound).");
    return;
  }

  const formData = new FormData();
  formData.append("sip_pcap", sipPcapInput.files[0]);
  formData.append("call_direction", callDirectionInput.value.trim().toLowerCase());
  formData.append("debug", String(DEBUG_ENABLED ? "1" : "0"));

  try {
    correlateInFlight = true;
    setUiMode(UI_MODE.CORRELATING);
    correlationWaitAbortController = new AbortController();
    updateCorrelationUiState();
    setCorrelationProgress(true);
    startCorrelationLiveLogPolling();
    finalResults.hidden = true;
    finalResults.innerHTML = "";
    addLog("info", `Starting correlation for SIP pcap: ${sipPcapInput.files[0].name}`);

    const queued = await api("/api/jobs/correlate", { method: "POST", body: formData });
    activeCorrelationJobId = String(queued.job_id || "");
    addLog("info", `Correlation job queued job_id=${queued.job_id}`);
    const data = await waitForCorrelationJob(queued.job_id, {
      timeoutMs: CORRELATION_TIMEOUT_MS,
      signal: correlationWaitAbortController.signal,
      onProgress: (() => {
        let lastBeat = 0;
        return ({ status, elapsedMs }) => {
          const now = Date.now();
          if ((now - lastBeat) < 15000) return;
          lastBeat = now;
          const step = String(status?.progress_step || "correlation");
          addLog("info", `Correlation running step=${step} elapsed=${Math.round(elapsedMs / 1000)}s`);
        };
      })(),
      onEvents: (events) => {
        for (const ev of events) {
          const lvl = String(ev?.level || "info").toLowerCase();
          const msg = String(ev?.message || "").trim();
          if (!msg) continue;
          addLog(lvl, msg);
        }
      },
    });
    logServerLines(data.log_tail || []);
    addLog("info", `Correlation finished encrypted_likely=${Boolean(data.encrypted_likely)}`);

    const hasDownloads =
      data.final_files &&
      (data.final_files.encrypted_media || data.final_files.decrypted_media || data.final_files.sip_plus_decrypted_media);

    if (hasDownloads) {
      renderFinalFiles(data.final_files);
      addLog("info", "Final files ready for download.");
    } else {
      const message = String(data.message || "No RTP/SRTP streams were found for the uploaded SIP pcap.");
      renderCorrelationNotice(message, "warn");
      setStatus(message, true);
      addLog("warn", message);
      addLog("warn", "No downloadable outputs were produced. Check logs (Debug) for details.");
    }
  } catch (err) {
    if (err?.name === "AbortError") {
      addLog("warn", "Correlation canceled by user.");
      setStatus("Correlation canceled by user.");
      renderCorrelationNotice("Correlation canceled. You can run a new correlation.", "warn");
      return;
    }
    if (Array.isArray(err.log_tail) && err.log_tail.length) {
      logServerLines(err.log_tail);
    }
    addLog("error", `Correlation failed: ${err.message}`);
    setStatus(`Correlation failed: ${err.message}`, true);
  } finally {
    activeCorrelationJobId = "";
    correlationWaitAbortController = null;
    stopCorrelationLiveLogPolling();
    setCorrelationProgress(false);
    correlateInFlight = false;
    setUiMode(UI_MODE.POST_CAPTURE);
    updateCorrelationUiState();
  }
});

cancelCorrelationBtn?.addEventListener("click", () => {
  if (!correlateInFlight || !correlationWaitAbortController) return;
  const jobId = String(activeCorrelationJobId || "").trim();
  if (jobId) {
    void api(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" })
      .then(() => addLog("warn", `Cancellation requested for correlation job_id=${jobId}`))
      .catch((err) => addLog("warn", `Could not request backend cancellation for job_id=${jobId}: ${err.message || err}`));
  }
  correlationWaitAbortController.abort();
});

stopFlushBtn?.addEventListener("click", () => {
  stopStorageFlush();
});

resumeFlushBtn?.addEventListener("click", () => {
  resumeStorageFlush();
});

sipPcapInput.addEventListener("change", updateCorrelationUiState);
callDirectionInput.addEventListener("change", updateCorrelationUiState);

downloadLogBtn.addEventListener("click", () => {
  const stamp = new Date().toISOString().replaceAll(":", "").replaceAll(".", "");
  const filename = `rtp-capture-tool-logs-${stamp}.txt`;
  const body = logEntries.map((e) => `${e.ts} ${String(e.level || "info").toUpperCase()} ${e.message}`).join("\n");
  const blob = new Blob([body + "\n"], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

clearLogBtn.addEventListener("click", () => {
  logEntries = [];
  logSeq = 0;
  logNeedsFullRender = true;
  if (logRenderTimer) {
    clearTimeout(logRenderTimer);
    logRenderTimer = null;
  }
  renderAppLog();
});

stayOnCaptureBtn?.addEventListener("click", () => {
  closeCaptureLeaveModal();
});

leaveAndCancelBtn?.addEventListener("click", async () => {
  const action = pendingLeaveAction;
  const ok = await cancelActiveCaptureForNavigation();
  if (!ok) return;
  closeCaptureLeaveModal();
  if (typeof action === "function") {
    action();
  }
});

window.addEventListener("beforeunload", (event) => {
  if (!captureRunning) return;
  const warning = "An active capture is running and will be cancelled if you leave this page.";
  event.preventDefault();
  event.returnValue = warning;
  return warning;
});

window.addEventListener("pagehide", () => {
  stopCaptureOnPageLeave();
});

(async () => {
  try {
    initLogWorker();
    setLogsVisible(true);
    setCorrelationProgress(false);
    setPostCaptureEntryMode("capture");
    resetCaptureLocationSelection();
    await initializeLogOffsetsFromCurrentFiles();
    startLogStreaming();
    await syncUiWithServerCaptureState();
    updateCorrelationUiState();
  } catch (err) {
    setStatus(err.message, true);
    addLog("error", err.message);
  }
})();
