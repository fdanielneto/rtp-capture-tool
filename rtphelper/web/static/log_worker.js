function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
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

function inlineTitleForMessage(msg) {
  const cleaned = String(msg || "").replace(/^INFO:\s*/i, "").trim();
  const stepMatch = cleaned.match(/^(Step\s+\d+\s+\([^)]+\)):/i);
  if (stepMatch) return stepMatch[1].toUpperCase();
  const idx = cleaned.search(/\b[A-Za-z_][\w-]*=/);
  const head = idx > 0 ? cleaned.slice(0, idx) : "";
  return head.replace(/[:(]\s*$/, "").trim().toUpperCase();
}

function extractInlineKeyValues(message) {
  const msg = String(message || "");
  const kv = [];
  for (const m of msg.matchAll(/\b([A-Za-z_][\w-]*)=(\S+)/g)) {
    kv.push({ key: m[1], value: m[2] });
  }
  const stepMatch = msg.match(/Step\s+(\d+)\s+\(([^)]+)\):\s*filter\s+(.+)/i);
  if (stepMatch) {
    kv.unshift({ key: "STEP", value: stepMatch[1] });
    kv.splice(1, 0, { key: "LEG", value: stepMatch[2] });
    kv.push({ key: "FILTER", value: stepMatch[3].trim() });
  }
  const pcapMatch = msg.match(/^Starting correlation for SIP pcap:\s*(.+)$/i);
  if (pcapMatch) {
    kv.push({ key: "PCAP", value: pcapMatch[1].trim() });
  }
  const packetMatch = msg.match(/\bpacket\s*#\s*(\d+)/i);
  if (packetMatch) {
    kv.push({ key: "PACKET", value: packetMatch[1] });
  }
  return kv;
}

function prioritizeInlineFields(items) {
  const priority = [
    "METHOD",
    "INLINE",
    "SUITE",
    "PACKET",
    "PACKETS",
    "PACKET_NUMBER",
    "SELECTED_INVITE_PACKET",
    "SELECTED_200OK_PACKET",
    "ENCRYPTED_DETECTED",
    "LEG",
    "STEP",
    "FIRST_INVITE_SRC",
    "LAST_HOST",
    "FIRST_INVITE_PACKET",
    "LAST_PACKET_INVITE",
    "CALL_ID",
  ];
  const bucket = new Map(priority.map((k, i) => [k, i]));
  const normalized = items.map((item, idx) => {
    const upper = String(item.key || "").toUpperCase();
    return { item, idx, rank: bucket.has(upper) ? bucket.get(upper) : 9999 };
  });
  normalized.sort((a, b) => (a.rank - b.rank) || (a.idx - b.idx));
  return normalized.map((x) => x.item);
}

function isUploadMetricKey(key) {
  const k = String(key || "").toLowerCase();
  return k === "upload_seconds" || k === "upload_mibps" || k === "upload_mbps";
}

function inlineKeyValueRow(items) {
  return items
    .map((item) => {
      const metricCls = isUploadMetricKey(item.key) ? " log-kv-metric" : "";
      return (
        `<span class="log-kv-key${metricCls}">${escapeHtml(item.key)}</span>=` +
        `<span class="log-kv-value${metricCls}">${escapeHtml(item.value)}</span>`
      );
    })
    .join(' <span class="log-inline-sep">|</span> ');
}

function formatStructuredProjectMessage(message) {
  const msg = String(message || "").trim();
  if (/^(?:INFO:\s*)?FILTER:/i.test(msg)) {
    return `<span class="log-filter-line">${escapeHtml(msg)}</span>`;
  }
  if (/^(?:INFO:\s*)?\[[^\]]+\]\s+FILTER:\s*".*"$/i.test(msg)) {
    return `<span class="log-filter-line">${escapeHtml(msg)}</span>`;
  }
  const title = inlineTitleForMessage(msg);
  const kv = prioritizeInlineFields(extractInlineKeyValues(msg));
  if (!kv.length) {
    return `<span class="log-inline-title">${escapeHtml(title || msg)}</span>`;
  }
  if (!title) {
    const directionItem = kv.find((item) => String(item.key || "").toUpperCase() === "DIRECTION");
    const roleItem = kv.find((item) => String(item.key || "").toUpperCase() === "ROLE");
    if (directionItem || roleItem) {
      const head = [
        directionItem ? `DIRECTION=${directionItem.value}` : "",
        roleItem ? `ROLE=${roleItem.value}` : "",
      ]
        .filter(Boolean)
        .join(" ");
      const tailItems = kv.filter((item) => {
        const k = String(item.key || "").toUpperCase();
        return k !== "DIRECTION" && k !== "ROLE";
      });
      if (tailItems.length) {
        return `<span class="log-inline-title">${escapeHtml(head)}</span> <span class="log-inline-sep">|</span> ${inlineKeyValueRow(tailItems)}`;
      }
      return `<span class="log-inline-title">${escapeHtml(head)}</span>`;
    }
    return inlineKeyValueRow(kv);
  }
  return `<span class="log-inline-title">${escapeHtml(title)}</span> <span class="log-inline-sep">|</span> ${inlineKeyValueRow(kv)}`;
}

self.onmessage = (event) => {
  const data = event?.data || {};
  if (data.type !== "parseProjectLines") return;
  const reqId = Number(data.reqId || 0);
  const lines = Array.isArray(data.lines) ? data.lines : [];
  const entries = lines.map((ln) => {
    const parsed = parseStructuredLine(ln);
    const message = parsed.message || stripStructuredPrefix(ln);
    return {
      level: logLevelFromStructuredLine(ln),
      message,
      displayTs: parsed.timestamp || null,
      displayLevel: parsed.level || null,
      structured: true,
      preformattedBody: formatStructuredProjectMessage(message),
    };
  });
  self.postMessage({ type: "parsedProjectLines", reqId, entries });
};
