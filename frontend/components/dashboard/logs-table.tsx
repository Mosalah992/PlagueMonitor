"use client"

import { useState } from "react"
import { formatDistanceToNow, format } from "date-fns"
import { FileText, ChevronDown, ChevronUp } from "lucide-react"

interface InfectionEvent {
  event_id: string
  run_id: string
  source_agent: string | null
  target_agent: string
  vector: string
  outcome: string
  severity: string
  confidence: number
  notes: string | null
  timestamp: string
}

interface LogsTableProps {
  logs: InfectionEvent[]
  total: number
  selectedAgent: string
  selectedEventType: string
  onAgentChange: (value: string) => void
  onEventTypeChange: (value: string) => void
  agents: { agent_id: string; name: string | null }[]
}

const eventTypes = ["all", "success", "failed", "blocked", "intercepted"]

function getOutcomeColor(type: string) {
  switch (type) {
    case "success":
      return "bg-destructive/20 text-destructive" // Infection success is destructive for the population
    case "failed":
      return "bg-success/20 text-success"
    case "blocked":
      return "bg-info/20 text-info"
    case "intercepted":
      return "bg-warning/20 text-warning"
    default:
      return "bg-secondary text-secondary-foreground"
  }
}

export function LogsTable({
  logs,
  total,
  selectedAgent,
  selectedEventType,
  onAgentChange,
  onEventTypeChange,
  agents,
}: LogsTableProps) {
  const [expandedLog, setExpandedLog] = useState<string | null>(null)

  return (
    <div className="flex flex-col gap-0 rounded-3xl glass overflow-hidden shadow-2xl">
      <div className="flex flex-col gap-6 border-b border-white/10 bg-white/5 px-8 py-6 md:flex-row md:items-center">
        <div className="flex items-center gap-4">
          <div className="relative rounded-2xl bg-info/20 p-2.5">
            <FileText className="h-6 w-6 text-info" />
            <div className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-[#0a0a0a] bg-info pulse-slow" />
          </div>
          <div>
            <h2 className="text-xl font-black tracking-tight text-foreground">Simulation Events</h2>
            <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/50">
              Infection Telemetry Stream
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 md:ml-auto">
          <div className="flex items-center gap-2 rounded-full bg-white/5 px-4 py-1.5 border border-white/5 mr-4">
            <span className="text-xs font-black text-foreground">{total.toLocaleString()}</span>
            <span className="text-[10px] font-bold uppercase tracking-tighter text-muted-foreground/60">Total Events</span>
          </div>
          
          <div className="flex gap-2">
            <select
              value={selectedAgent}
              onChange={(e) => onAgentChange(e.target.value)}
              className="rounded-xl border border-white/10 bg-black/40 px-4 py-2 text-xs font-bold text-foreground focus:outline-none focus:ring-2 focus:ring-info/50 appearance-none cursor-pointer hover:bg-black/60 transition-colors"
            >
              <option value="all">All Agents</option>
              {agents.map((agent) => (
                <option key={agent.agent_id} value={agent.agent_id}>
                  {agent.name || agent.agent_id}
                </option>
              ))}
            </select>
            <select
              value={selectedEventType}
              onChange={(e) => onEventTypeChange(e.target.value)}
              className="rounded-xl border border-white/10 bg-black/40 px-4 py-2 text-xs font-bold text-foreground focus:outline-none focus:ring-2 focus:ring-info/50 appearance-none cursor-pointer hover:bg-black/60 transition-colors"
            >
              {eventTypes.map((type) => (
                <option key={type} value={type}>
                  {type === "all" ? "All Outcomes" : type.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/5 text-left text-xs font-bold uppercase tracking-widest text-muted-foreground/60">
              <th className="px-6 py-4">Time</th>
              <th className="px-6 py-4">Source</th>
              <th className="px-6 py-4">Target</th>
              <th className="px-6 py-4">Vector</th>
              <th className="px-6 py-4">Outcome</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {logs.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-6 py-12 text-center text-sm font-medium text-muted-foreground/50"
                >
                  No simulation events recorded
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <>
                  <tr
                    key={log.event_id}
                    className="transition-colors hover:bg-white/5 group"
                  >
                    <td className="px-6 py-4">
                      <div className="flex flex-col">
                        <span className="text-sm font-bold text-foreground">
                          {format(new Date(log.timestamp), "HH:mm:ss")}
                        </span>
                        <span className="text-[10px] font-black uppercase tracking-tighter text-muted-foreground/50">
                          {formatDistanceToNow(new Date(log.timestamp), {
                            addSuffix: true,
                          })}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <code className="rounded bg-black/40 px-2 py-1 font-mono text-xs font-semibold text-foreground/80">
                        {log.source_agent || "Environment"}
                      </code>
                    </td>
                    <td className="px-6 py-4">
                      <code className="rounded bg-black/40 px-2 py-1 font-mono text-xs font-semibold text-info/80">
                        {log.target_agent}
                      </code>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-xs font-bold text-muted-foreground">
                        {log.vector}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`rounded-lg border px-2 py-1 text-[10px] font-black uppercase tracking-widest ${getOutcomeColor(log.outcome)}`}
                      >
                        {log.outcome}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                       <span className={`text-xs font-black uppercase ${log.severity === 'high' ? 'text-destructive' : 'text-muted-foreground'}`}>
                         {log.severity}
                       </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                        <button
                          onClick={() =>
                            setExpandedLog(
                              expandedLog === log.event_id ? null : log.event_id
                            )
                          }
                          className="flex items-center gap-1 text-xs font-bold text-info transition-colors hover:text-info/80"
                        >
                          {expandedLog === log.event_id ? (
                            <>
                              Hide <ChevronUp className="h-4 w-4" />
                            </>
                          ) : (
                            <>
                              View <ChevronDown className="h-4 w-4" />
                            </>
                          )}
                        </button>
                    </td>
                  </tr>
                  {expandedLog === log.event_id && (
                    <tr key={`${log.event_id}-payload`}>
                      <td
                        colSpan={7}
                        className="bg-black/40 px-6 py-6"
                      >
                        <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                          <p className="mb-2 text-xs font-bold text-muted-foreground uppercase tracking-widest">Event Notes</p>
                          <p className="text-sm text-foreground/90 italic">"{log.notes || 'No telemetry notes available for this encounter.'}"</p>
                          <div className="mt-4 grid grid-cols-2 gap-4">
                             <div>
                                <p className="text-[10px] font-bold text-muted-foreground uppercase">Confidence</p>
                                <p className="text-sm font-mono text-info">{(log.confidence * 100).toFixed(1)}%</p>
                             </div>
                             <div>
                                <p className="text-[10px] font-bold text-muted-foreground uppercase">Run ID</p>
                                <p className="text-sm font-mono text-muted-foreground/60">{log.run_id}</p>
                             </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
