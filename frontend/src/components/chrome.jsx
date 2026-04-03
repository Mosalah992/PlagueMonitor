import { formatDate, formatTime, toneClasses } from "../data";

export function Header({ activeTab, setActiveTab, alertCount, clock }) {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800 bg-[#080c11]/95 backdrop-blur">
      <div className="flex flex-wrap items-center justify-between gap-4 px-3 py-4">
        <div className="flex min-w-[260px] items-center gap-4">
          <div className="flex items-center gap-1 font-pixel text-[13px] uppercase tracking-[0.2em] text-terminal-cyan">
            <span>[EPI::SIEM]</span>
            <span className="animate-blink text-terminal-success">_</span>
          </div>
          <div className="font-mono text-[11px] text-slate-500">v2.4.1-alpha</div>
        </div>
        <nav className="flex flex-wrap items-center gap-1 font-pixel text-[7px] uppercase text-slate-500">
          <TabButton label="SIMULATION" active={activeTab === "simulation"} onClick={() => setActiveTab("simulation")} />
          <TabButton label="SEARCH" active={activeTab === "search"} onClick={() => setActiveTab("search")} />
          <TabButton label="LIVE_MONITOR" active={activeTab === "live"} pulseDot onClick={() => setActiveTab("live")} />
        </nav>
        <div className="ml-auto flex min-w-[300px] flex-wrap items-center justify-end gap-4">
          <div className="border border-terminal-danger/30 bg-terminal-danger/10 px-3 py-1 font-pixel text-[6px] uppercase text-terminal-danger">
            {alertCount.toString().padStart(2, "0")} alerts
          </div>
          <div className="flex items-center gap-2 font-pixel text-[7px] uppercase text-terminal-success">
            <span className="status-dot-live inline-block h-2 w-2 rounded-full bg-terminal-success" />
            <span>SIEM_ONLINE</span>
          </div>
          <div className="text-right font-mono">
            <div className="text-[24px] leading-none text-slate-100">{formatTime(clock)}</div>
            <div className="mt-1 text-[11px] text-slate-500">{formatDate(clock)}</div>
          </div>
        </div>
      </div>
    </header>
  );
}

export function SubHeader({ breadcrumb, threatLevel, activeAgents, infectedCount }) {
  return (
    <div className="border-b border-slate-900 bg-[#0a0e14] px-3 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="font-mono text-[12px] text-terminal-cyan/85">{breadcrumb}</div>
        <div className="flex flex-wrap items-center gap-5 font-pixel text-[6px] uppercase">
          <MiniStat label="THREAT_LEVEL" value={threatLevel.toUpperCase()} tone="amber" />
          <MiniStat label="ACTIVE_AGENTS" value={String(activeAgents)} tone="green" />
          <MiniStat label="INFECTED" value={String(infectedCount)} tone="red" />
        </div>
      </div>
    </div>
  );
}

export function SectionHeader({ label }) {
  return (
    <div className="flex items-center gap-3">
      <div className="font-pixel text-[8px] uppercase text-terminal-cyan">{`> ${label}`}</div>
      <div className="section-line flex-1" />
    </div>
  );
}

export function FooterBar() {
  return (
    <footer className="mt-6 border-t border-slate-900 py-4 font-mono text-[10px] text-slate-700">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span>EPI-SIEM (C) 2026 | EPIDEMIOLOGY SECURITY INFORMATION & EVENT MANAGEMENT</span>
        <span>KERNEL:4.19.2 DB:0xEF21A RULES:8,847</span>
      </div>
    </footer>
  );
}

function TabButton({ label, active, onClick, pulseDot = false }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`relative border-b-2 px-4 py-3 transition ${
        active ? "border-terminal-cyan bg-terminal-cyan/10 text-terminal-cyan" : "border-transparent hover:bg-terminal-cyan/5 hover:text-terminal-cyan"
      }`}
    >
      {label}
      {pulseDot ? <span className="absolute right-2 top-2 h-1.5 w-1.5 animate-pulse rounded-full bg-terminal-danger" /> : null}
    </button>
  );
}

function MiniStat({ label, value, tone }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-slate-600">{label}:</span>
      <span className={toneClasses(tone)}>{value}</span>
    </div>
  );
}
