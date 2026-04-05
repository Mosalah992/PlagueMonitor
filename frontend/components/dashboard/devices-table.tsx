"use client"

import { formatDistanceToNow } from "date-fns"
import { Users } from "lucide-react"

interface Agent {
  id: string
  agent_id: string
  name: string | null
  role: string
  status: string
  infection_score: number
  last_event_at: string
  position_x: number
  position_y: number
}

interface DevicesTableProps {
  agents: Agent[]
}

export function DevicesTable({ agents }: DevicesTableProps) {
  const getStatusColor = (status: string, score: number) => {
    if (status === "infected" || score > 0.7) return "bg-destructive shadow-[0_0_10px_rgba(var(--destructive),0.5)]"
    if (status === "exposed") return "bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]"
    if (status === "recovered") return "bg-info shadow-[0_0_10px_rgba(var(--info),0.5)]"
    return "bg-success shadow-[0_0_10px_rgba(var(--success),0.5)]"
  }

  return (
    <div className="overflow-hidden">
      <div className="flex items-center gap-3 border-b border-white/10 p-6">
        <div className="rounded-lg bg-info/20 p-2">
          <Users className="h-5 w-5 text-info" />
        </div>
        <h2 className="text-xl font-bold tracking-tight text-foreground">Agent Population</h2>
        <span className="ml-auto rounded-full bg-white/5 px-3 py-1 text-xs font-bold text-muted-foreground">
          {agents.length} Agents
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/5 text-left text-xs font-bold uppercase tracking-widest text-muted-foreground/60">
              <th className="px-6 py-4">Health</th>
              <th className="px-6 py-4">Agent ID</th>
              <th className="px-6 py-4">Name</th>
              <th className="px-6 py-4">Role</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Infection Score</th>
              <th className="px-6 py-4 text-right">Position</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {agents.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-6 py-12 text-center text-sm font-medium text-muted-foreground/50"
                >
                  No agents in current simulation
                </td>
              </tr>
            ) : (
              agents.map((agent) => (
                <tr
                  key={agent.id}
                  className="transition-colors hover:bg-white/5"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <div className={`h-2.5 w-2.5 rounded-full ${getStatusColor(agent.status, agent.infection_score)}`} title={agent.status} />
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-foreground">
                      {agent.agent_id}
                    </code>
                  </td>
                  <td className="px-6 py-4 text-sm font-bold text-foreground">
                    {agent.name || "—"}
                  </td>
                  <td className="px-6 py-4">
                    <span className="rounded-lg bg-info/10 px-2 py-1 text-xs font-bold text-info border border-info/20 uppercase tracking-tighter">
                      {agent.role}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-xs font-bold uppercase text-muted-foreground/70">
                      {agent.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                     <div className="h-1.5 w-24 rounded-full bg-white/5 overflow-hidden">
                        <div 
                          className={`h-full transition-all ${agent.infection_score > 0.5 ? 'bg-destructive' : 'bg-info'}`}
                          style={{ width: `${agent.infection_score * 100}%` }}
                        />
                     </div>
                  </td>
                  <td className="px-6 py-4 text-right font-mono text-[10px] text-muted-foreground/60">
                    [{agent.position_x.toFixed(1)}, {agent.position_y.toFixed(1)}]
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
