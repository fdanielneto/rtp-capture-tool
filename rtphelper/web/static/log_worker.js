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

function formatStructuredProjectMessage(message) {
  const msg = String(message || "").trim();
  if (shouldKeepLineWhite(msg)) {
    return `<span class="log-token-value">${escapeHtml(msg)}</span>`;
  }
  let escaped = escapeHtml(msg);
  escaped = escaped.replace(/^\[(carrier-rtpengine|rtpengine-carrier|rtpengine-core|core-rtpengine)\]\s*/i, "");

  const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const colorFieldEquals = (text, fields, cls) => {
    if (!fields.length) return text;
    const names = fields.map(escapeRegex).join("|");
    return text.replace(new RegExp(`(^|[^\\w])(${names})=([^\\s|"]+)`, "gi"), (m, prefix, key, value) => {
      return `${prefix}<span class="${cls}">${key}=</span><span class="log-token-value">${value}</span>`;
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
      "last_packet_invite",
      "analysis_packet",
      "invite_cipher_packet",
      "200ok_cipher_packet",
      "carrier_invite_packet",
      "carrier_200ok_packet",
      "core_invite_packet",
      "invite_packet_number",
      "reply_packet_number",
      "packet_number",
      "file",
      "name",
    ],
    "log-token-pink"
  );
  escaped = escaped.replace(
    /\[(media_stream_from_carrier_to_rtpengine|media_stream_from_rtpengine_to_carrier|media_stream_from_rtpengine_to_core|media_stream_from_core_to_rtpengine)\]/gi,
    '<span class="log-token-yellow">[$1]</span>'
  );
  escaped = escaped.replace(
    /\[(carrier-rtpengine|rtpengine-carrier|rtpengine-core|core-rtpengine)\]/gi,
    '<span class="log-token-yellow">[$1]</span>'
  );
  escaped = escaped.replace(
    /^(\s*)(LEG:\s*CARRIER\s*-\s*RTP ENGINE|LEG:\s*RTP ENGINE\s*-\s*CORE)/i,
    '$1<span class="log-token-value">$2</span>'
  );

  escaped = escaped.replace(/COMBINED FILTER:/gi, '<span class="log-token-filter-yellow">COMBINED FILTER:</span>');
  escaped = escaped.replace(/(^|[^A-Z])FILTER:/g, (m, prefix) => `${prefix}<span class="log-token-filter-yellow">FILTER:</span>`);
  escaped = escaped.replace(
    /\b(packets=)(\d+)(\s+KEEP)\b/gi,
    '$1$2<span class="log-token-green">$3</span>'
  );

  return `<span class="log-filter-line">${escaped}</span>`;
}

function shouldKeepLineWhite(message) {
  const msg = String(message || "").trim();
  if (!msg) return false;
  if (/^=+\s*Step\s+[1-6]:.*=+\s*$/i.test(msg)) return true;
  if (/^SIP CORRELATION ANALYSIS$/i.test(msg)) return true;
  if (/^=+\s*SIP CORRELATION ANALYSIS\s*=+\s*$/i.test(msg)) return true;
  if (/^=+\s*RTP Engine IP Detection\s*=+\s*$/i.test(msg)) return true;
  if (/^=+$/.test(msg)) return true;
  if (/^-+$/.test(msg)) return true;
  return false;
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
