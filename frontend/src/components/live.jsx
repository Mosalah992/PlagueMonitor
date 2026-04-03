import { LIVE_FILTERS, eventTypeClass, severityTextClass, toneClasses } from "../data";
import { SectionHeader } from "./chrome";

function liveFilterTone(filter) {
  if (filter === "all") return "cyan";
  if (filter === "block" || filter === "alert") return "amber";
  if (filter === "mutation") return "purple";
  if (filter === "infection" || filter === "exfil") return "red";
  if (filter === "query" || filter === "transfer") return "blue";
  return "green";
}

export function LiveTab({
  liveMetrics,
  livePaused,
  setLivePaused,
  liveFilter,
  setLiveFilter,
  visibleLiveEvents,
  onClear,
  onExport,
  liveFeedRef,
  onScroll,
  sessionId,
  liveConnected,
  onRefresh
}) {
  return (
    <section className="space-y-5 px-3 py-5">
      <SectionHeader label="LIVE_METRICS" />
      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-7">
        {liveMetrics.cards.map((card) => (
          <div key={card.label} className="terminal-panel p-4 text-center">
            <div className="font-pixel text-[5px] uppercase text-slate-600">{card.label}</div>
            <div className={`mt-4 font-mono text-[34px] leading-none ${card.valueClass}`}>{card.value}</div>
            <div className="mt-4 flex items-center justify-center">
              <span className={`h-2 w-2 rounded-full ${card.dotClass}`} />
            </div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setLivePaused((value) => !value)}
            className={`border px-4 py-3 font-pixel text-[7px] uppercase ${livePaused ? "border-terminal-success/40 bg-terminal-success/10 text-terminal-success" : "border-terminal-warn/40 bg-terminal-warn/10 text-terminal-warn"}`}
          >
            {livePaused ? "> RESUME_STREAM" : "|| PAUSE_STREAM"}
          </button>
          {LIVE_FILTERS.map((filter) => (
            <button
              key={filter}
              type="button"
              onClick={() => setLiveFilter(filter)}
              className={`border px-3 py-3 font-pixel text-[6px] uppercase ${liveFilter === filter ? toneClasses(liveFilterTone(filter), true) : "border-slate-700 text-slate-500"}`}
            >
              {filter.toUpperCase()}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={onRefresh} className="border border-terminal-success/30 px-4 py-3 font-pixel text-[6px] uppercase text-terminal-success">
            REFRESH
          </button>
          <button type="button" onClick={onClear} className="border border-slate-700 px-4 py-3 font-pixel text-[6px] uppercase text-slate-400">
            CLEAR
          </button>
          <button type="button" onClick={onExport} className="border border-terminal-cyan/30 px-4 py-3 font-pixel text-[6px] uppercase text-terminal-cyan">
            EXPORT
          </button>
          <div className="flex items-center gap-2 font-pixel text-[7px] uppercase text-terminal-success">
            <span className={`inline-block h-2 w-2 rounded-full ${livePaused || !liveConnected ? "bg-slate-600" : "bg-terminal-success status-dot-live"}`} />
            {livePaused ? "STREAM PAUSED" : "LIVE"}
          </div>
        </div>
      </div>

      <div className="terminal-panel">
        <div ref={liveFeedRef} onScroll={onScroll} className="h-[440px] overflow-y-auto bg-[#080c11] px-4 py-3 font-mono text-[12px]">
          {visibleLiveEvents.map((event) => (
            <div key={event.id} className={`mb-3 border border-slate-900 bg-[#0b1016] p-3 ${event.beaconed ? "border-l-2 border-l-terminal-cyan" : ""}`}>
              <div className="mb-2 flex flex-wrap items-center gap-3">
                <span className="text-slate-600">[{event.timestamp}]</span>
                <span className={`font-semibold ${eventTypeClass(event.type)}`}>{event.type}</span>
                <span className={event.severity === "INFO" ? "severity-dim" : severityTextClass(event.severity)}>{event.severity}</span>
                {event.beaconed ? <span className="border border-terminal-cyan bg-terminal-cyan/10 px-2 py-0.5 text-[10px] text-terminal-cyan">BEACONED</span> : null}
              </div>
              <div className="text-slate-300">
                <span className="text-terminal-info">{event.src}</span>
                <span className="mx-2 text-slate-700">-&gt;</span>
                <span className="text-terminal-purple">{event.dst}</span>
                <span className="ml-3 text-slate-500">{event.attackType || "no attack_type"}</span>
                <span className="ml-3 text-slate-600">reset={event.resetId || "-"}</span>
              </div>
              <div className="mt-2 text-[11px] text-slate-500">
                {[event.bytes ? `bytes=${event.bytes}` : "", event.proto ? `proto=${event.proto}` : "", event.dstCountry ? `country=${event.dstCountry}` : "", event.detail].filter(Boolean).join(" | ")}
              </div>
              <div className="mt-2 border border-slate-900 bg-[#0a0f15] p-2 text-[11px] text-slate-500">
                <div>hash={event.payloadHash || "(empty)"} | family={event.semanticFamily || "(empty)"} | mutation={event.mutationType || "(empty)"} | v={event.mutationVersion || "-"}</div>
                <div>decode={event.decodeStatus || "(none)"} | wrapper={event.payloadWrapperType || "(empty)"}</div>
                {event.hasPayload ? <div className="mt-1 text-slate-400">raw: {event.payloadPreview || "No payload."}</div> : null}
                {event.hasDecodedPayload ? <div className="mt-1 text-slate-400">decoded: {event.decodedPayloadPreview || ""}</div> : null}
              </div>
            </div>
          ))}
          {!livePaused ? <div className="pt-1 font-mono text-terminal-cyan animate-blink">|</div> : null}
        </div>
        <div className="border-t border-slate-900 px-4 py-3 font-mono text-[10px] text-slate-600">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>stream:{livePaused ? "PAUSED" : "LIVE"} | filter:{liveFilter.toUpperCase()} | buffer:{visibleLiveEvents.length}/100 | reset:{liveMetrics.currentResetId || "-"} | epoch:{liveMetrics.currentEpoch ?? "-"}</span>
            <span>parse_errors:{liveMetrics.parseErrors ?? 0} | session_id:{sessionId} | {liveMetrics.lastEventTs || new Date().toISOString()}</span>
          </div>
        </div>
      </div>
    </section>
  );
}
