import React, { useEffect, useMemo, useRef, useState } from "react";
import { fetchJson } from "./api";
import { FooterBar, Header, SubHeader } from "./components/chrome";
import { LiveTab } from "./components/live";
import { SearchTab } from "./components/search";
import { SimulationTab } from "./components/simulation";
import {
  FALLBACK_EVENTS,
  TAB_LABELS,
  buildFallbackHints,
  buildFieldPivots,
  buildIntelligenceCards,
  buildPatternCards,
  buildSimulationMetrics,
  buildStatsCards,
  buildTimelineData,
  computeLiveMetrics,
  deriveAgentCards,
  normalizeLiveEvent,
  normalizeSearchEvent,
} from "./data";

function App() {
  const [activeTab, setActiveTab] = useState("simulation");
  const [difficulty, setDifficulty] = useState("medium");
  const [simRunning, setSimRunning] = useState(false);
  const [controlStatus, setControlStatus] = useState("system idle :: control plane nominal");
  const [controlState, setControlState] = useState(null);
  const [healthState, setHealthState] = useState(null);
  const [clock, setClock] = useState(new Date());
  const [searchMode, setSearchMode] = useState("structured");
  const [timeRange, setTimeRange] = useState("last_1h");
  const [searchQuery, setSearchQuery] = useState("event=INFECTION_SUCCESSFUL");
  const [activeSearchRun, setActiveSearchRun] = useState("active_infections");
  const [activeSearchFilter, setActiveSearchFilter] = useState("all");
  const [searchTab, setSearchTab] = useState("events");
  const [searchBusy, setSearchBusy] = useState(false);
  const [searchPayload, setSearchPayload] = useState(null);
  const [statsPayload, setStatsPayload] = useState(null);
  const [fieldsPayload, setFieldsPayload] = useState(null);
  const [hintsPayload, setHintsPayload] = useState(null);
  const [queryHelp, setQueryHelp] = useState(null);
  const [selectedEventId, setSelectedEventId] = useState("");
  const [livePaused, setLivePaused] = useState(false);
  const [liveFilter, setLiveFilter] = useState("all");
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveLatestId, setLiveLatestId] = useState(0);
  const [liveMetricsPayload, setLiveMetricsPayload] = useState(null);
  const [liveConnected, setLiveConnected] = useState(true);
  const liveFeedRef = useRef(null);
  const liveAutoScrollRef = useRef(true);
  const liveLatestIdRef = useRef(0);
  const searchRequestRef = useRef(0);
  const [sessionId] = useState(() => `SIM_${Math.floor(11 + Math.random() * 999999).toString(16).padStart(6, "0")}`);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    fetchQueryHelp();
    refreshControlState();
    refreshLive(true);
    runSearch("event=INFECTION_SUCCESSFUL");
    const timer = window.setInterval(refreshControlState, 6000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!simRunning) return undefined;
    const interval = window.setInterval(runSimulationPulse, 15000);
    return () => window.clearInterval(interval);
  }, [simRunning, difficulty]);

  useEffect(() => {
    if (livePaused) return undefined;
    const interval = window.setInterval(() => {
      refreshLive();
    }, 1500);
    return () => window.clearInterval(interval);
  }, [livePaused]);

  useEffect(() => {
    liveLatestIdRef.current = liveLatestId;
  }, [liveLatestId]);

  useEffect(() => {
    const node = liveFeedRef.current;
    if (!node || !liveAutoScrollRef.current) return;
    node.scrollTop = node.scrollHeight;
  }, [liveEvents, activeTab]);

  const searchEvents = useMemo(() => {
    const apiEvents = (searchPayload?.events || []).map(normalizeSearchEvent);
    const events = apiEvents.length ? apiEvents : FALLBACK_EVENTS;

    if (activeSearchFilter === "all") return events;

    return events.filter((event) => {
      const eventType = event.event_type.toLowerCase();
      return eventType.includes(activeSearchFilter) || event.severity.toLowerCase() === activeSearchFilter;
    });
  }, [activeSearchFilter, searchPayload]);

  const selectedEvent = useMemo(
    () => searchEvents.find((event) => event.id === selectedEventId) || searchEvents[0] || null,
    [searchEvents, selectedEventId]
  );

  useEffect(() => {
    if (!searchEvents.length) {
      setSelectedEventId("");
      return;
    }

    const hasSelectedEvent = searchEvents.some((event) => event.id === selectedEventId);
    if (!hasSelectedEvent) {
      setSelectedEventId(searchEvents[0].id);
    }
  }, [searchEvents, selectedEventId]);

  const agents = useMemo(() => deriveAgentCards(controlState), [controlState]);
  const simMetrics = useMemo(() => buildSimulationMetrics(controlState, healthState, simRunning), [controlState, healthState, simRunning]);
  const breadcrumb = `epi / siem / ${TAB_LABELS[activeTab]}`;
  const infectedCount = useMemo(() => agents.filter((agent) => agent.state === "INFECTED").length, [agents]);
  const alertCount = useMemo(() => {
    const criticalSearch = searchEvents.filter((event) => event.severity === "CRITICAL").length;
    const criticalLive = liveEvents.filter((event) => event.severity === "CRITICAL").length;
    return criticalSearch + criticalLive + infectedCount;
  }, [infectedCount, liveEvents, searchEvents]);
  const liveMetrics = useMemo(() => computeLiveMetrics(liveEvents, liveMetricsPayload), [liveEvents, liveMetricsPayload]);
  const visibleLiveEvents = useMemo(() => {
    if (liveFilter === "all") return liveEvents;
    return liveEvents.filter((event) => event.type.toLowerCase().includes(liveFilter));
  }, [liveEvents, liveFilter]);
  const sidebarPivots = useMemo(() => buildFieldPivots(searchEvents), [searchEvents]);
  const timelineBars = useMemo(() => buildTimelineData(searchPayload?.timeline), [searchPayload]);
  const statisticsCards = useMemo(() => buildStatsCards(statsPayload), [statsPayload]);
  const patternCards = useMemo(() => buildPatternCards(searchPayload, statsPayload), [searchPayload, statsPayload]);
  const intelligenceCards = useMemo(() => buildIntelligenceCards(searchPayload, statsPayload, hintsPayload), [searchPayload, statsPayload, hintsPayload]);

  async function refreshControlState() {
    try {
      const [control, health] = await Promise.all([fetchJson("/dashboard/state"), fetchJson("/api/health")]);
      setControlState(control);
      setHealthState(health);
      setLiveConnected(true);
    } catch (error) {
      setLiveConnected(false);
      setControlStatus(`telemetry degraded :: ${error.message}`);
    }
  }

  async function fetchQueryHelp() {
    try {
      setQueryHelp(await fetchJson("/api/query-help"));
    } catch {
      setQueryHelp(null);
    }
  }

  async function refreshLive(forceFull = false) {
    try {
      const params = new URLSearchParams({
        after_id: forceFull ? "0" : String(liveLatestIdRef.current),
        limit: "120",
        q: ""
      }).toString();
      const payload = await fetchJson(`/api/live?${params}`);
      const normalizedEvents = (payload.events || []).map(normalizeLiveEvent);

      setLiveConnected(true);
      setLiveMetricsPayload(payload.metrics || null);
      setLiveLatestId(Number(payload.latest_id || 0));
      setLiveEvents((previous) => {
        if (forceFull || !liveLatestIdRef.current) {
          return normalizedEvents;
        }
        const seen = new Set(previous.map((event) => event.id));
        const merged = [...previous];
        normalizedEvents.forEach((event) => {
          if (!seen.has(event.id)) {
            merged.push(event);
          }
        });
        return merged.slice(-100);
      });
    } catch (error) {
      setLiveConnected(false);
      setControlStatus(`live stream degraded :: ${error.message}`);
    }
  }

  async function runSearch(queryOverride = searchQuery) {
    const requestId = searchRequestRef.current + 1;
    searchRequestRef.current = requestId;
    setSearchBusy(true);

    try {
      const params = new URLSearchParams({ q: queryOverride, mode: searchMode, time_range: timeRange }).toString();
      const [search, stats, fields, hints] = await Promise.all([
        fetchJson(`/api/search?${params}&limit=24`),
        fetchJson(`/api/stats?${params}`),
        fetchJson(`/api/fields?${params}`),
        fetchJson(`/api/hints?${params}`)
      ]);

      if (requestId !== searchRequestRef.current) return;

      setSearchPayload(search);
      setStatsPayload(stats);
      setFieldsPayload(fields);
      setHintsPayload(hints);
      setControlStatus(`query executed :: ${queryOverride || "all events"} :: ${search.total ?? search.events?.length ?? 0} rows`);
    } catch (error) {
      if (requestId !== searchRequestRef.current) return;

      setSearchPayload(null);
      setStatsPayload(null);
      setFieldsPayload(null);
      setHintsPayload(null);
      setControlStatus(`query failure :: ${error.message}`);
    } finally {
      if (requestId === searchRequestRef.current) {
        setSearchBusy(false);
      }
    }
  }

  async function postControl(endpoint, body) {
    const payload = await fetchJson(endpoint, {
      method: "POST",
      body: JSON.stringify(body ?? {})
    });
    setControlStatus(`${endpoint} :: ${JSON.stringify(payload)}`);
    await refreshControlState();
    return payload;
  }

  async function runSimulationPulse() {
    const wormLevel = difficulty === "hard" || difficulty === "nightmare" ? "difficult" : difficulty;

    try {
      await postControl("/inject/agent-c", { worm_level: wormLevel });
      await refreshLive(true);
    } catch (error) {
      setControlStatus(`simulation pulse failed :: ${error.message}`);
    }
  }

  async function handleControlAction(action) {
    if (action === "run") {
      setSimRunning(true);
      await runSimulationPulse();
      return;
    }

    if (action === "pause") {
      setSimRunning(false);
      setControlStatus("simulation paused :: auto-injection halted");
      return;
    }

    if (action === "vaccine") {
      await postControl("/vaccine");
      await refreshLive(true);
      setControlStatus("vaccine deployed :: temporary defense boost active");
      return;
    }

    if (action === "quarantine") {
      await postControl("/quarantine/agent-c");
      await refreshLive(true);
      return;
    }

    if (action === "reset") {
      setSimRunning(false);
      await postControl("/reset");
      await refreshLive(true);
    }
  }

  function handleLiveScroll(event) {
    const node = event.currentTarget;
    liveAutoScrollRef.current = node.scrollTop + node.clientHeight >= node.scrollHeight - 24;
  }

  function handleSaveSearch(run) {
    setActiveSearchRun(run.id);
    setSearchQuery(run.query);
    runSearch(run.query);
  }

  function applyScopeShortcut(scope) {
    if (scope === "current_reset" && liveMetrics.currentResetId) {
      const query = `reset_id=${liveMetrics.currentResetId}`;
      setSearchQuery(query);
      runSearch(query);
    }
    if (scope === "current_run" && liveMetrics.currentResetId && liveMetrics.currentEpoch !== undefined) {
      const query = `reset_id=${liveMetrics.currentResetId} AND epoch=${liveMetrics.currentEpoch}`;
      setSearchQuery(query);
      runSearch(query);
    }
  }

  function exportLiveFeed() {
    const blob = new Blob([JSON.stringify(visibleLiveEvents, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `epidemic-live-${Date.now()}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="min-h-screen bg-terminal-base text-slate-200 terminal-grid">
      <div className="crt-overlay" />
      <div className="mx-auto flex min-h-screen max-w-[1600px] flex-col px-4 pb-4 pt-3">
        <Header activeTab={activeTab} setActiveTab={setActiveTab} alertCount={alertCount} clock={clock} />
        <SubHeader breadcrumb={breadcrumb} activeAgents={simMetrics.agentsOnline.value} infectedCount={infectedCount} threatLevel={simMetrics.infectionRate.subLabel} />
        <main className="flex-1">
          <div key={activeTab} className="tab-enter">
            {activeTab === "simulation" ? (
              <SimulationTab difficulty={difficulty} setDifficulty={setDifficulty} metrics={simMetrics} agents={agents} controlStatus={controlStatus} onControlAction={handleControlAction} />
            ) : null}
            {activeTab === "search" ? (
              <SearchTab
                activeSearchRun={activeSearchRun}
                onSaveSearch={handleSaveSearch}
                searchQuery={searchQuery}
                setSearchQuery={setSearchQuery}
                searchMode={searchMode}
                setSearchMode={setSearchMode}
                timeRange={timeRange}
                setTimeRange={setTimeRange}
                activeSearchFilter={activeSearchFilter}
                setActiveSearchFilter={setActiveSearchFilter}
                searchTab={searchTab}
                setSearchTab={setSearchTab}
                searchBusy={searchBusy}
                onRunSearch={runSearch}
                searchEvents={searchEvents}
                selectedEvent={selectedEvent}
                setSelectedEventId={setSelectedEventId}
                timelineBars={timelineBars}
                sidebarPivots={sidebarPivots}
                statisticsCards={statisticsCards}
                patternCards={patternCards}
                intelligenceCards={intelligenceCards}
                fieldsPayload={fieldsPayload}
                queryHelp={queryHelp}
                hints={hintsPayload?.hints || buildFallbackHints()}
                liveContext={liveMetrics}
                onApplyScopeShortcut={applyScopeShortcut}
              />
            ) : null}
            {activeTab === "live" ? (
              <LiveTab
                liveMetrics={liveMetrics}
                livePaused={livePaused}
                setLivePaused={setLivePaused}
                liveFilter={liveFilter}
                setLiveFilter={setLiveFilter}
                visibleLiveEvents={visibleLiveEvents}
                onClear={() => setLiveEvents([])}
                onExport={exportLiveFeed}
                liveFeedRef={liveFeedRef}
                onScroll={handleLiveScroll}
                sessionId={sessionId}
                liveConnected={liveConnected}
                onRefresh={() => refreshLive(true)}
              />
            ) : null}
          </div>
        </main>
        <FooterBar />
      </div>
    </div>
  );
}

export default App;
