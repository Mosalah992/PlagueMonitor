export const TAB_LABELS = {
  simulation: "simulation",
  search: "search",
  live: "live_monitor"
};

export const SEARCH_RUNS = [
  { id: "active_infections", label: "ACTIVE_INFECTIONS", query: "event=INFECTION_SUCCESSFUL" },
  { id: "mutation_trace", label: "MUTATION_TRACE", query: "mutation_v>=1" },
  { id: "c2_beacons", label: "C2_BEACONS", query: "event contains \"BEACON\" OR event=QUERY" },
  { id: "exfil_detect", label: "EXFIL_DETECT", query: "event contains \"EXFIL\" OR severity=CRITICAL" }
];

export const SEARCH_FILTERS = [
  { id: "all", label: "ALL", tone: "cyan" },
  { id: "infection", label: "INFECTION", tone: "red" },
  { id: "mutation", label: "MUTATION", tone: "purple" },
  { id: "block", label: "BLOCK", tone: "amber" },
  { id: "transfer", label: "TRANSFER", tone: "blue" },
  { id: "beacon", label: "BEACON", tone: "cyan" },
  { id: "exfil", label: "EXFIL", tone: "red" },
  { id: "query", label: "QUERY", tone: "green" }
];

export const RESULT_TABS = ["events", "patterns", "statistics", "visualization", "intelligence"];
export const LIVE_FILTERS = ["all", "infection", "mutation", "block", "query", "transfer", "exfil", "scan", "alert"];

export const DIFFICULTIES = [
  { id: "easy", label: "EASY", tone: "green" },
  { id: "medium", label: "MEDIUM", tone: "cyan" },
  { id: "hard", label: "HARD", tone: "amber" },
  { id: "nightmare", label: "NIGHTMARE", tone: "red" }
];

export const FALLBACK_AGENTS = [
  {
    id: "AGT-001",
    ip: "192.168.1.47",
    subnet: "SUBNET-ALPHA",
    state: "HEALTHY",
    eventCount: 142,
    uptime: 99.2,
    activity: [
      { ts: "14:23:01", text: "BARRIER_PING received", tone: "gray" },
      { ts: "14:22:47", text: "Routine scan: 0 threats", tone: "gray" },
      { ts: "14:21:33", text: "Packet filtered: 10.0.0.99", tone: "green" }
    ]
  },
  {
    id: "AGT-002",
    ip: "192.168.1.23",
    subnet: "SUBNET-BETA",
    state: "INFECTED",
    eventCount: 891,
    uptime: 67.8,
    activity: [
      { ts: "14:23:05", text: "REPLICATION attempt detected", tone: "red" },
      { ts: "14:23:01", text: "Payload injection: 0xDEAD", tone: "red" },
      { ts: "14:22:58", text: "Quarantine override FAILED", tone: "red" }
    ]
  },
  {
    id: "AGT-003",
    ip: "192.168.1.91",
    subnet: "SUBNET-ALPHA",
    state: "BLOCKED",
    eventCount: 2341,
    uptime: 45.1,
    activity: [
      { ts: "14:22:55", text: "QUARANTINE active - isolated", tone: "amber" },
      { ts: "14:22:30", text: "Mutation seq: 0x4F2A detected", tone: "amber" },
      { ts: "14:21:55", text: "Outbound blocked: 5 packets", tone: "amber" }
    ]
  },
  {
    id: "AGT-004",
    ip: "192.168.2.15",
    subnet: "SUBNET-GAMMA",
    state: "HEALTHY",
    eventCount: 67,
    uptime: 99.9,
    activity: [
      { ts: "14:23:02", text: "Heartbeat OK - nominal", tone: "green" },
      { ts: "14:22:45", text: "Full scan: 0 threats found", tone: "gray" },
      { ts: "14:22:00", text: "Firewall rules synced", tone: "gray" }
    ]
  },
  {
    id: "AGT-005",
    ip: "192.168.2.78",
    subnet: "SUBNET-DELTA",
    state: "MUTATION",
    eventCount: 456,
    uptime: 78.3,
    activity: [
      { ts: "14:23:03", text: "MUTATION_V3 strain detected", tone: "purple" },
      { ts: "14:22:51", text: "Genetic drift: +0.23 sigma", tone: "purple" },
      { ts: "14:22:39", text: "Payload hash changed: 0xC0DE", tone: "amber" }
    ]
  },
  {
    id: "AGT-006",
    ip: "192.168.2.33",
    subnet: "SUBNET-GAMMA",
    state: "INFECTED",
    eventCount: 1203,
    uptime: 52.7,
    activity: [
      { ts: "14:23:09", text: "C2 beacon detected: port 4444", tone: "red" },
      { ts: "14:22:59", text: "EXFIL attempt: 14.2KB data", tone: "red" },
      { ts: "14:22:44", text: "DNS poison attempt blocked", tone: "amber" }
    ]
  }
];

export const FALLBACK_EVENTS = [
  ["14:23:05.123", "INFECTION", "AGT-002", "AGT-007", "0xDEADBEEF", "CRITICAL", "SUBNET-BETA", 16384, 443],
  ["14:23:03.891", "MUTATION", "AGT-005", "BROADCAST", "0x4F2A9C31", "HIGH", "SUBNET-DELTA", 812, 0],
  ["14:23:01.445", "BLOCK", "BARRIER-A", "AGT-002", "0x00000000", "LOW", "SUBNET-ALPHA", 64, 22],
  ["14:22:59.007", "EXFIL", "AGT-006", "203.0.113.7", "0xC0FFEE11", "CRITICAL", "SUBNET-GAMMA", 24612, 443],
  ["14:22:57.334", "QUERY", "AGT-004", "DNS-01", "0x00000000", "INFO", "SUBNET-GAMMA", 128, 53],
  ["14:22:55.882", "BEACON", "AGT-006", "203.0.113.7", "0xBADC0DE5", "CRITICAL", "SUBNET-GAMMA", 1024, 4444],
  ["14:22:53.101", "MUTATION", "AGT-005", "AGT-011", "0x7F3A1B9E", "HIGH", "SUBNET-DELTA", 928, 8080],
  ["14:22:51.668", "TRANSFER", "AGT-001", "AGT-009", "0x12345678", "INFO", "SUBNET-ALPHA", 4096, 9001],
  ["14:22:49.223", "BLOCK", "BARRIER-B", "AGT-005", "0x00000000", "MEDIUM", "SUBNET-DELTA", 128, 3389],
  ["14:22:47.009", "INFECTION", "AGT-003", "AGT-008", "0xDEADBEEF", "CRITICAL", "SUBNET-ALPHA", 14200, 445],
  ["14:22:45.447", "QUERY", "AGT-004", "DB-INT", "0x00000000", "LOW", "SUBNET-GAMMA", 88, 5432],
  ["14:22:43.012", "TRANSFER", "AGT-001", "AGT-006", "0x8A1D44EF", "INFO", "SUBNET-ALPHA", 1337, 8443]
].map(([timestamp, event_type, src_agent, dst_agent, payload_hash, severity, subnet, bytes_transferred, dest_port], idx) => ({
  id: `mock-${idx}`,
  timestamp,
  event_type,
  src_agent,
  dst_agent,
  payload_hash,
  severity,
  subnet,
  bytes_transferred,
  dest_port
}));

const LIVE_EVENT_TYPES = [
  { type: "HEARTBEAT", weight: 22, severity: "INFO", detail: "heartbeat_ok seq={seq} jitter={value}ms" },
  { type: "BLOCK", weight: 18, severity: "HIGH", detail: "firewall_rule={value} packet_drop={bytes}" },
  { type: "QUERY", weight: 18, severity: "INFO", detail: "proto:DNS resolve:epi-{value}.internal" },
  { type: "TRANSFER", weight: 12, severity: "LOW", detail: "bytes:{bytes} proto:TCP flags:PSH,ACK" },
  { type: "SCAN", weight: 10, severity: "LOW", detail: "ports_scanned:{bytes} open:{value} technique:SYN_STEALTH" },
  { type: "ALERT", weight: 8, severity: "MEDIUM", detail: "rule:SIGMA_{value} correlation:pattern_match confidence:{percent}%" },
  { type: "MUTATION", weight: 6, severity: "HIGH", detail: "mutation_chain=v{value} hash=0x{hash}" },
  { type: "INFECTION", weight: 4, severity: "CRITICAL", detail: "payload:0x{hash} replication_attempt=true" },
  { type: "EXFIL", weight: 2, severity: "CRITICAL", detail: "bytes:{bytes} proto:HTTPS dst_country:{country}" }
];

export function toneClasses(tone, active = false) {
  const palette = {
    cyan: active ? "border-terminal-cyan/40 bg-terminal-cyan/10 text-terminal-cyan" : "text-terminal-cyan",
    green: active ? "border-terminal-success/40 bg-terminal-success/10 text-terminal-success" : "text-terminal-success",
    red: active ? "border-terminal-danger/40 bg-terminal-danger/10 text-terminal-danger" : "text-terminal-danger",
    amber: active ? "border-terminal-warn/40 bg-terminal-warn/10 text-terminal-warn" : "text-terminal-warn",
    blue: active ? "border-terminal-info/40 bg-terminal-info/10 text-terminal-info" : "text-terminal-info",
    purple: active ? "border-terminal-purple/40 bg-terminal-purple/10 text-terminal-purple" : "text-terminal-purple"
  };
  return palette[tone] || (active ? "border-slate-700 text-slate-300" : "text-slate-300");
}

export function eventTypeClass(type) {
  const normalized = String(type || "").toUpperCase();
  if (normalized.includes("INFECT") || normalized.includes("EXFIL") || normalized.includes("ALERT")) return "text-terminal-danger";
  if (normalized.includes("MUTATION")) return "text-terminal-purple";
  if (normalized.includes("BLOCK")) return "text-terminal-warn";
  if (normalized.includes("TRANSFER")) return "text-terminal-cyan";
  if (normalized.includes("QUERY") || normalized.includes("BEACON")) return "text-terminal-info";
  if (normalized.includes("SCAN") || normalized.includes("HEART")) return "text-terminal-success";
  return "text-slate-400";
}

export function severityBadgeClass(severity) {
  switch (severity) {
    case "CRITICAL":
      return "border-terminal-danger/40 bg-terminal-danger/10 text-terminal-danger";
    case "HIGH":
      return "border-terminal-warn/40 bg-terminal-warn/10 text-terminal-warn";
    case "MEDIUM":
      return "border-terminal-cyan/40 bg-terminal-cyan/10 text-terminal-cyan";
    case "LOW":
      return "border-terminal-success/40 bg-terminal-success/10 text-terminal-success";
    default:
      return "border-slate-700 bg-slate-800/40 text-slate-500";
  }
}

export function severityTextClass(severity) {
  switch (severity) {
    case "CRITICAL":
      return "text-terminal-danger";
    case "HIGH":
      return "text-terminal-warn";
    case "MEDIUM":
      return "text-terminal-cyan";
    case "LOW":
      return "text-terminal-success";
    default:
      return "text-slate-500";
  }
}

export function activityTone(tone) {
  switch (tone) {
    case "red":
      return "text-terminal-danger";
    case "amber":
      return "text-terminal-warn";
    case "purple":
      return "text-terminal-purple";
    case "green":
      return "text-terminal-success";
    default:
      return "text-slate-500";
  }
}

export function stateTone(state) {
  switch (state) {
    case "INFECTED":
      return { dot: "#f87171", border: "rgba(248,113,113,0.45)", badge: "rgba(248,113,113,0.4)" };
    case "BLOCKED":
      return { dot: "#fbbf24", border: "rgba(251,191,36,0.42)", badge: "rgba(251,191,36,0.35)" };
    case "MUTATION":
      return { dot: "#c084fc", border: "rgba(192,132,252,0.38)", badge: "rgba(192,132,252,0.35)" };
    default:
      return { dot: "#4ade80", border: "rgba(74,222,128,0.28)", badge: "rgba(74,222,128,0.35)" };
  }
}

export function formatTime(date) {
  return date.toLocaleTimeString("en-GB", { hour12: false });
}

export function formatDate(date) {
  return date.toLocaleDateString("en-GB").replace(/\//g, "-");
}

export function formatApiTimestamp(value) {
  if (!value) return "00:00:00.000";
  const parsed = Number(value);
  if (Number.isFinite(parsed)) {
    return new Date(parsed * 1000).toLocaleTimeString("en-GB", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  }
  return String(value).slice(11, 23) || String(value);
}

export function normalizeSearchEvent(event, index = 0) {
  const metadata = event.metadata || {};
  return {
    id: event.event_id || event.id || `api-${index}`,
    timestamp: formatApiTimestamp(event.ts),
    event_type: String(event.event || metadata.event_type || "EVENT").toUpperCase(),
    src_agent: event.src || metadata.src_agent || "AGT-001",
    dst_agent: event.dst || metadata.dst_agent || "AGT-002",
    payload_hash: event.payload_hash || metadata.payload_hash || "0x00000000",
    severity: deriveSeverity(event, metadata),
    subnet: metadata.reset_id ? `RESET-${String(metadata.reset_id).slice(0, 4)}` : "SUBNET-ALPHA",
    bytes_transferred: Number(metadata.payload_length || event.payload_length || 0),
    dest_port: Number(metadata.dest_port || 443)
  };
}

function deriveSeverity(event, metadata) {
  const raw = String(metadata.severity || event.attack_type || event.event || "").toUpperCase();
  if (raw.includes("CRITICAL") || raw.includes("INFECTION") || raw.includes("EXFIL")) return "CRITICAL";
  if (raw.includes("MUTATION") || raw.includes("HIGH")) return "HIGH";
  if (raw.includes("BLOCK") || raw.includes("WARN")) return "MEDIUM";
  if (raw.includes("TRANSFER")) return "LOW";
  return "INFO";
}

export function isBeaconedLiveEvent(event) {
  const src = String(event.src || "").toLowerCase();
  const dst = String(event.dst || "").toLowerCase();
  const type = String(event.type || event.event || "").toUpperCase();
  return (
    (type === "TRANSFER" &&
      ["agent-a", "agt-001", "agt-01"].includes(src) &&
      ["agent-b", "agent-c", "agt-002", "agt-003", "agt-02", "agt-03"].includes(dst)) ||
    (type === "EXFIL" && /^agt[-_]?0*[4-9]$/i.test(String(event.dst || "")))
  );
}

export function normalizeLiveEvent(event, index = 0) {
  const metadata = event.metadata || {};
  const type = String(event.event || metadata.event_type || "EVENT").toUpperCase();
  const payloadLength = Number(event.payload_length || metadata.payload_length || metadata.bytes || metadata.bytes_transferred || 0);
  const detailParts = [
    event.attack_type || metadata.attack_type || "",
    payloadLength > 0 ? `bytes:${payloadLength}` : "",
    metadata.proto ? `proto:${metadata.proto}` : "",
    metadata.dst_country ? `country:${metadata.dst_country}` : ""
  ].filter(Boolean);

  return {
    id: event.event_id || event.id || `live-api-${index}`,
    timestamp: formatApiTimestamp(event.ts),
    ts: event.ts || "",
    type,
    event: type,
    src: event.src || metadata.src_agent || "AGT-001",
    dst: event.dst || metadata.dst_agent || "AGT-002",
    severity: deriveSeverity(event, metadata),
    attackType: event.attack_type || metadata.attack_type || "",
    detail: detailParts.join(" | "),
    bytes: payloadLength,
    proto: metadata.proto || "",
    dstCountry: metadata.dst_country || "",
    payloadHash: event.payload_hash || metadata.payload_hash || "",
    semanticFamily: event.semantic_family || metadata.semantic_family || "",
    mutationType: event.mutation_type || metadata.mutation_type || "",
    mutationVersion: event.mutation_v ?? metadata.mutation_v ?? "",
    decodeStatus: event.decode_status || metadata.decode_status || "",
    payloadWrapperType: event.payload_wrapper_type || metadata.payload_wrapper_type || "",
    payloadPreview: event.payload_preview || metadata.payload_preview || "",
    decodedPayloadPreview: event.decoded_payload_preview || metadata.decoded_payload_preview || "",
    hasPayload: Boolean(event.has_payload),
    hasDecodedPayload: Boolean(event.has_decoded_payload),
    resetId: event.reset_id || metadata.reset_id || "",
    epoch: event.epoch ?? metadata.epoch ?? "",
    beaconed: isBeaconedLiveEvent({ type, src: event.src || metadata.src_agent || "", dst: event.dst || metadata.dst_agent || "" })
  };
}

export function countBy(values) {
  const counts = values.reduce((accumulator, value) => {
    const key = String(value || "UNKNOWN");
    accumulator.set(key, (accumulator.get(key) || 0) + 1);
    return accumulator;
  }, new Map());
  return Array.from(counts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count);
}

export function buildFieldPivots(events) {
  const groups = {
    src_agent: countBy(events.map((event) => event.src_agent)),
    event_type: countBy(events.map((event) => event.event_type)),
    severity: countBy(events.map((event) => event.severity))
  };
  return Object.fromEntries(
    Object.entries(groups).map(([key, values]) => {
      const max = values[0]?.count || 1;
      return [
        key,
        values.slice(0, 4).map((entry) => ({
          ...entry,
          percent: Math.max(12, Math.round((entry.count / max) * 100))
        }))
      ];
    })
  );
}

export function buildTimelineData(timeline) {
  if (Array.isArray(timeline) && timeline.length) {
    return timeline.slice(-20).map((item, index) => ({
      label: item.label || item.bucket || `${index}`,
      value: Number(item.value || item.count || 0)
    }));
  }
  return Array.from({ length: 20 }, (_, index) => ({
    label: index === 0 ? "14:06" : index === 10 ? "14:17" : index === 19 ? "14:35" : "",
    value: [1, 4, 2, 6, 9, 3, 7, 12, 5, 8, 5, 2, 11, 7, 1, 4, 6, 10, 3, 5][index]
  }));
}

export function buildFallbackHints() {
  return [
    "AGT-002 shows lateral movement pattern",
    "critical severities cluster around SUBNET-BETA",
    "payload hashes 0xDEADBEEF and 0xC0FFEE11 recur across infection and exfil events",
    "mutation traffic spikes after barrier resets"
  ];
}

export function deriveAgentCards(controlState) {
  if (!controlState?.agents) return FALLBACK_AGENTS;
  const mapped = Object.values(controlState.agents).map((agent, index) => {
    const template = FALLBACK_AGENTS[index % FALLBACK_AGENTS.length];
    const rawState = String(agent.state || "healthy").toUpperCase();
    const state = rawState === "RESISTANT" ? "BLOCKED" : rawState === "EXPOSED" ? "MUTATION" : rawState;
    return {
      ...template,
      id: String(agent.id || template.id).replace("agent-", "AGT-00"),
      state,
      eventCount: Number(agent.last_metadata?.last_message_metadata?.payload_length || template.eventCount),
      activity: template.activity
    };
  });
  return mapped.length ? mapped : FALLBACK_AGENTS;
}

export function buildSimulationMetrics(controlState, healthState, simRunning) {
  const agents = deriveAgentCards(controlState);
  const infected = agents.filter((agent) => agent.state === "INFECTED").length;
  const blocked = agents.filter((agent) => agent.state === "BLOCKED").length;
  return {
    agentsOnline: {
      label: "AGENTS_ONLINE",
      value: controlState?.agents ? Object.keys(controlState.agents).length : 42,
      valueClass: "text-slate-300",
      subLabel: simRunning ? `+ ${Math.max(agents.length - infected, 0)} ACTIVE` : "STANDBY",
      subClass: "text-terminal-success",
      accent: "from-terminal-cyan/90 via-terminal-cyan/35 to-transparent"
    },
    infectionRate: {
      label: "INFECTION_RATE",
      value: `${(((infected || 1) / Math.max(agents.length || 6, 1)) * 100).toFixed(1)}%`,
      valueClass: infected >= 2 ? "text-terminal-warn" : "text-terminal-success",
      subLabel: infected >= 2 ? "CRITICAL" : "NOMINAL",
      subClass: infected >= 2 ? "text-terminal-danger" : "text-terminal-success",
      accent: infected >= 2 ? "from-terminal-danger/80 via-terminal-warn/30 to-transparent" : "from-terminal-success/80 via-terminal-cyan/30 to-transparent"
    },
    barriersActive: {
      label: "BARRIERS_ACTIVE",
      value: blocked + 8,
      valueClass: "text-slate-300",
      subLabel: "NOMINAL",
      subClass: "text-terminal-success",
      accent: "from-terminal-cyan/90 via-terminal-cyan/35 to-transparent"
    },
    threatsNeutralized: {
      label: "THREATS_NEUTRALIZED",
      value: healthState?.indexed_events || 891,
      valueClass: "text-slate-300",
      subLabel: "delta -12/MIN",
      subClass: "text-terminal-success",
      accent: "from-terminal-success/80 via-terminal-cyan/20 to-transparent"
    }
  };
}

export function buildStatsCards(statsPayload) {
  if (!statsPayload) {
    return [
      { title: "EVENT_COUNTS", tone: "cyan", lines: ["infection_successful=23", "infection_blocked=891", "avg_attack_strength=0.72"] },
      { title: "TARGET_DISTRIBUTION", tone: "blue", lines: ["AGT-002 => 32", "AGT-005 => 12", "AGT-007 => 8"] },
      { title: "HOP_DISTRIBUTION", tone: "purple", lines: ["hop_0 => 12", "hop_1 => 9", "hop_2 => 4"] }
    ];
  }
  return [
    {
      title: "EVENT_COUNTS",
      tone: "cyan",
      lines: [`successful=${statsPayload.successful}`, `blocked=${statsPayload.blocked}`, `attempts=${statsPayload.attempts}`]
    },
    {
      title: "SUCCESS_RATE_BY_TARGET",
      tone: "blue",
      lines: (statsPayload.presets?.success_rate_by_dst || []).slice(0, 3).map((item) => `${item.dst || "unknown"} => ${(item.success_rate * 100).toFixed(1)}%`)
    },
    {
      title: "ATTACK_STRENGTH",
      tone: "amber",
      lines: [
        `avg_attack_strength=${statsPayload.avg_attack_strength}`,
        `distinct_attacks=${statsPayload.count_by_attack_type?.length || 0}`,
        `query=${statsPayload.structured_query || "(empty)"}`
      ]
    }
  ];
}

export function buildPatternCards(searchPayload, statsPayload) {
  const warnings = searchPayload?.warnings || [];
  return [
    {
      title: "ROUTE_PATTERNS",
      tone: "cyan",
      lines: statsPayload?.src_dst_frequency?.slice(0, 4).map((item) => `${item.src} -> ${item.dst} (${item.count})`) || [
        "AGT-002 -> AGT-007 (5)",
        "AGT-005 -> BROADCAST (2)",
        "AGT-006 -> 203.0.113.7 (3)"
      ]
    },
    {
      title: "SUPPRESSION_PATTERNS",
      tone: "amber",
      lines: warnings.length ? warnings.slice(0, 4) : ["BARRIER-B suppressed 4 outbound replication attempts", "mutation_v3 repeatedly blocked by SUBNET-ALPHA"]
    }
  ];
}

export function buildIntelligenceCards(searchPayload, statsPayload, hintsPayload) {
  return [
    {
      title: "MUTATION_INTELLIGENCE",
      tone: "purple",
      lines: [
        `top_hash=${searchPayload?.events?.[0]?.payload_hash || "0xDEADBEEF"}`,
        `families=${statsPayload?.count_by_attack_type?.length || 4}`,
        "dominant_mutation=reframe"
      ]
    },
    {
      title: "CAMPAIGN_SUMMARY",
      tone: "blue",
      lines: ["campaign_id=cmp_1775208253_agent-c", "deepest_target=agent-a", "objective=SPREAD_FAST"]
    },
    {
      title: "ANALYST_NOTES",
      tone: "amber",
      lines: (hintsPayload?.hints || buildFallbackHints()).slice(0, 3).map((hint) => (typeof hint === "string" ? hint : hint.title || hint.reason || hint.message))
    }
  ];
}

export function seedLiveEvents() {
  return Array.from({ length: 27 }, (_, index) => createLiveEvent(index + 1));
}

export function appendLiveEvent(previous) {
  const next = [...previous, createLiveEvent(previous.length + 1)];
  return next.slice(-100);
}

function createLiveEvent(sequence) {
  const profile = weightedChoice(LIVE_EVENT_TYPES);
  const src = `AGT-${String(1 + (sequence % 9)).padStart(3, "0")}`;
  const dst = sequence % 5 === 0 ? `203.0.113.${(sequence % 7) + 1}` : `AGT-${String(2 + ((sequence + 5) % 9)).padStart(3, "0")}`;
  const hash = randomHex(8);
  const bytes = 128 + ((sequence * 913) % 18000);
  const value = 1 + ((sequence * 17) % 999);
  const percent = 60 + (sequence % 30);
  const country = ["CN", "RU", "DE", "NL", "US"][sequence % 5];
  return {
    id: `live-${sequence}-${hash}`,
    timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false }),
    type: profile.type,
    src,
    dst,
    severity: profile.severity,
    detail: profile.detail
      .replace("{seq}", String(sequence).padStart(4, "0"))
      .replace("{value}", String(value))
      .replace("{bytes}", String(bytes))
      .replace("{percent}", String(percent))
      .replace("{hash}", hash)
      .replace("{country}", country)
  };
}

function weightedChoice(items) {
  const total = items.reduce((sum, item) => sum + item.weight, 0);
  let threshold = Math.random() * total;
  for (const item of items) {
    threshold -= item.weight;
    if (threshold <= 0) return item;
  }
  return items[items.length - 1];
}

function randomHex(length) {
  const alphabet = "0123456789ABCDEF";
  let value = "";
  for (let index = 0; index < length; index += 1) {
    value += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return value;
}

export function computeLiveMetrics(events, metrics = null) {
  const counts = {
    infection: events.filter((event) => event.type === "INFECTION").length,
    mutation: events.filter((event) => event.type === "MUTATION").length,
    block: events.filter((event) => event.type === "BLOCK").length,
    query: events.filter((event) => event.type === "QUERY").length,
    transfer: events.filter((event) => event.type === "TRANSFER").length,
    anomalies: events.filter((event) => event.severity === "CRITICAL").length
  };
  const source = metrics || {};
  return {
    currentResetId: source.last_reset_id || "",
    currentEpoch: source.current_epoch ?? 0,
    parseErrors: source.parse_errors ?? 0,
    lastEventTs: source.last_event_ts || "",
    cards: [
      { label: "EVENTS/SEC", value: Number(source.events_per_sec ?? Math.min(events.length, 44)).toFixed(1), valueClass: "text-terminal-cyan", dotClass: "bg-terminal-cyan shadow-cyan" },
      { label: "INFECTIONS", value: source.infections ?? counts.infection, valueClass: "text-terminal-danger", dotClass: "bg-terminal-danger" },
      { label: "MUTATIONS", value: counts.mutation, valueClass: "text-terminal-purple", dotClass: "bg-terminal-purple" },
      { label: "BLOCKS", value: source.blocked ?? counts.block, valueClass: "text-terminal-warn", dotClass: "bg-terminal-warn" },
      { label: "QUERIES", value: `${Math.max(counts.query, 0)}`, valueClass: "text-terminal-info", dotClass: "bg-terminal-info" },
      { label: "TRANSFERS", value: counts.transfer + 344, valueClass: "text-terminal-cyan", dotClass: "bg-terminal-cyan" },
      { label: "ANOMALIES", value: counts.anomalies || 3, valueClass: "text-terminal-danger", dotClass: "bg-terminal-danger" }
    ]
  };
}
