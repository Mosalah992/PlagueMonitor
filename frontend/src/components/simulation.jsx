import { DIFFICULTIES, activityTone, stateTone, toneClasses } from "../data";
import { SectionHeader } from "./chrome";

export function SimulationTab({ difficulty, setDifficulty, metrics, agents, controlStatus, onControlAction }) {
  return (
    <section className="space-y-5 px-3 py-5">
      <SectionHeader label="SIM_CONTROL" />
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-pixel text-[8px] uppercase text-slate-500">DIFFICULTY:</span>
        {DIFFICULTIES.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setDifficulty(item.id)}
            className={`border px-3 py-2 font-pixel text-[7px] uppercase ${difficulty === item.id ? toneClasses(item.tone, true) : "border-slate-700 text-slate-500"}`}
          >
            {item.label}
          </button>
        ))}
        <button type="button" onClick={() => onControlAction("run")} className="border border-terminal-success/40 bg-terminal-success/10 px-5 py-2 font-pixel text-[7px] uppercase text-terminal-success">
          &gt; RUN_SIM
        </button>
        <button type="button" onClick={() => onControlAction("pause")} className="border border-terminal-warn/40 bg-terminal-warn/10 px-5 py-2 font-pixel text-[7px] uppercase text-terminal-warn">
          || PAUSE_SIM
        </button>
        <button type="button" onClick={() => onControlAction("vaccine")} className="border border-terminal-purple/40 bg-terminal-purple/10 px-5 py-2 font-pixel text-[7px] uppercase text-terminal-purple">
          VACCINE
        </button>
        <button type="button" onClick={() => onControlAction("quarantine")} className="border border-terminal-warn/40 bg-terminal-warn/10 px-5 py-2 font-pixel text-[7px] uppercase text-terminal-warn">
          LOCK QUARANTINE_ALL
        </button>
        <button type="button" onClick={() => onControlAction("reset")} className="border border-slate-700 bg-slate-800/40 px-5 py-2 font-pixel text-[7px] uppercase text-slate-400">
          RESET
        </button>
      </div>
      <div className="font-mono text-[12px] text-slate-500">{controlStatus}</div>

      <SectionHeader label="METRICS" />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Object.values(metrics).map((metric) => (
          <MetricCard key={metric.label} metric={metric} />
        ))}
      </div>

      <SectionHeader label="AGENT_STATUS" />
      <div className="grid gap-4 xl:grid-cols-3">
        {agents.map((agent) => (
          <AgentCard key={agent.id} agent={agent} />
        ))}
      </div>

      <SectionHeader label="BARRIER_RESET_CONTROL" />
      <div className="terminal-panel flex flex-wrap items-center justify-between gap-4 p-4">
        <div className="flex flex-wrap gap-3">
          {["SUBNET-ALPHA", "SUBNET-BETA", "SUBNET-GAMMA", "SUBNET-DELTA"].map((subnet) => (
            <button key={subnet} type="button" className="border border-terminal-cyan/35 px-6 py-3 font-mono text-[12px] uppercase text-terminal-cyan">
              RESET {subnet}
            </button>
          ))}
        </div>
        <button type="button" className="border border-terminal-danger/35 bg-terminal-danger/10 px-6 py-3 font-pixel text-[7px] uppercase text-terminal-danger">
          ALERT RESET_ALL_BARRIERS
        </button>
      </div>
    </section>
  );
}

function MetricCard({ metric }) {
  return (
    <div className="terminal-panel relative overflow-hidden p-4">
      <div className={`absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r ${metric.accent}`} />
      <div className="font-pixel text-[6px] uppercase text-slate-500">{metric.label}</div>
      <div className={`mt-6 font-mono text-[26px] leading-none ${metric.valueClass}`}>{metric.value}</div>
      <div className={`mt-4 font-pixel text-[7px] uppercase ${metric.subClass}`}>{metric.subLabel}</div>
    </div>
  );
}

function AgentCard({ agent }) {
  const stateClass = stateTone(agent.state);

  return (
    <div className={`terminal-panel p-4 ${agent.state === "INFECTED" ? "infected-card" : ""}`} style={{ borderColor: stateClass.border }}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: stateClass.dot, boxShadow: `0 0 8px ${stateClass.dot}` }} />
          <div className="font-pixel text-[8px] uppercase text-slate-200">{agent.id}</div>
        </div>
        <div className="border px-2 py-1 font-pixel text-[6px] uppercase" style={{ color: stateClass.dot, borderColor: stateClass.badge }}>
          {agent.state}
        </div>
      </div>
      <div className="mt-4 font-mono text-[21px] text-terminal-info">{agent.ip}</div>
      <div className="mt-2 font-mono text-[12px] text-slate-600">
        {agent.subnet} | {agent.eventCount} EVT | {agent.uptime.toFixed(1)}% UP
      </div>
      <div className="my-4 h-px bg-slate-800" />
      <div className="space-y-2 font-mono text-[12px]">
        {agent.activity.map((entry, index) => (
          <div key={`${agent.id}-${index}`} className="flex gap-3">
            <span className="text-slate-600">{entry.ts}</span>
            <span className={activityTone(entry.tone)}>{entry.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
